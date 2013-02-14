#!/usr/bin/env perl


# steve ulrich <sulrich@cisco.com>
#
# script to conver a junos filter to an ios-xr object-group notation
# style ACL.  i'm sure stuff's broke in here.

use strict;
use warnings;
use Data::Dumper;
use Text::Balanced qw(extract_multiple extract_delimited extract_bracketed);


my %term_fields = (             # bracketed term fields
                   "destination-address"  => "",
                   "source-address"       => "",
                   # "from"               => "",
                   "then"                 => "",
                  );

my %term_atoms = (              # these are field terms we attempt to do
                                # something reasonable with
                   "protocol"         => "",
                   "destination-port" => "",
                   "source-port"      => "",
                   "forwarding-class" => "",
                   "count"            => "",
                   "accept"           => "",
                   "tcp-established"  => "",
                   "packet-length"    => "",
                  );


my @terms       = (); # all of the fw filter terms go in here.
my $term        = {}; # anonymous hash for pushing into @terms
my $term_cap    = 0;  # flag for capturing terms
my $term_name   = ""; # key for the term
my $filter_name = "";
my $c_net_obj   = "";
my $c_port_obj  = "";
my $c_acl_obj   = "";
my $acl_incr    = 10; # amount to increment ACL line #s by


# standard format for the translated objects is:
#
# -  object-group network ipv4 TERM_NAME-SRC/DST
# -  object-group port TERM_NAME-SRC/DST
#
# junos filter name will result in the same acl name on the IOS XR side

open(ACL, $ARGV[0]) || die "error opening: $ARGV[0]";
while (<ACL>) {
  if (/filter (\w\S+)\s+\{/i) {
    $filter_name = $1;               # we happen to have this in the file,
                                  # use it to name the acl
  }


  if (( /term (\w\S+)\s+\{/i ) && ($term_cap == 0)) {
    # this is the first term we're running into
    $term_cap  = 1;                          # start capturing
    $term_name = $1;

  } elsif (( /term (\w\S+)\s+\{/ ) && ($term_cap == 1)) {
    # we've bumped up against this is the next term for this filter
    #
    # the order of operations is important here!
    push @terms, $term;
    $term      = {};                  # reset this value
    $term_name = $1;
  }

  if ($term_cap == 1) {
    $term->{$term_name} .= $_;
  }
}
push @terms, $term;              # cleanup prior to closing the file.
close(ACL);



foreach my $i (0 .. $#terms) {       # handle terms in order
  foreach my $j (keys %{ $terms[$i] } ) {
    my $acl = &parseAclTerm( $j, $terms[$i]{$j} );

    my ($netobj, $portobj, $acl) = &processTerm($j, $acl);



  }
}


sub processTerm {
  my ($aclname, $aclref) = @_;

  my ($netobj, $portobj, $acl,
      $src_addr, $src_ports,
      $dst_addr, $dst_ports,
      $action, $counter) = "";

  my @protocols      = ('ip');
  my $netobj_prefix  = "object-group network ipv4";
  my $portobj_prefix = "object-group port ";
  my $src_net        = "$aclname-SRC";
  my $dst_net        = "$aclname-DST";
  my $s_port_name    = "$aclname-SRC_PORTS";
  my $d_port_name    = "$aclname-DST_PORTS";

  foreach my $field (keys %{ $aclref->{$aclname} }  ) {

    if ($field  =~ /destination-address/i ) {
      my $dst_addr_block = &parseAddrBlock( $aclref->{$aclname}->{$field} );
      $netobj .= $netobj_prefix . "$dst_net\n" . $dst_addr_block . "\n";
    }

    elsif ($field  =~ /source-address/i ) {
      my $src_addr_block = &parseAddrBlock( $aclref->{$aclname}->{$field} );
      $netobj .= $netobj_prefix . "$src_net\n" . $src_addr_block . "\n";
    }

    elsif ($field  =~ /protocol/i ) {
     @protocols = &parseProtocol( $aclref->{$aclname}->{$field} );
    }

    elsif ($field  =~ /source-port/i )         {
      $src_ports = &parsePortBlock( $aclref->{$aclname}->{$field} );
      $portobj .= $portobj_prefix . $aclname . "-SRC\n" . $src_ports . "\n";
    }

    elsif ($field  =~ /destination-port/i )    {
      $dst_ports = &parsePortBlock( $aclref->{$aclname}->{$field} );
      $portobj .= $portobj_prefix . $aclname . "-DST\n" . $dst_ports . "\n";
    }
    elsif ($field  =~ /then/i ) {
      $action = &parseAction( $aclref->{$aclname}->{$field} );
    }
  }

  my ($s_p, $d_p) = "";

  foreach my $prot (@protocols) {
    $s_p = "port-group $s_port_name" if ($src_ports ne "");
    $d_p = "port-group $d_port_name" if ($dst_ports ne "");

    $acl .= "$action $prot net-group $src_net $s_p net-group $dst_net $d_p" . "\n";
  }

  return ($netobj, $portobj, $acl);
}


sub parseProtocol {
  my ($str) = @_;
  $str =~ s/\[|\]|\;//g; # rip off the brackets
  $str =~ s/^\s+//g;
  $str =~ s/\s+$//g;     # cleanup whitespace

  my @protocols = split(/\s+/, $str);
  return @protocols;
}

sub parsePortBlock {
  my ($str) = @_;
  $str =~ s/\[|\]|\;//g; # rip off the brackets
  $str =~ s/^\s+//g;
  $str =~ s/\s+$//g;     # cleanup whitespace

  my @ports = split(/\s+/, $str);

  my $portblock = "";
  foreach my $p (@ports) {
    #$p =~ s/\s//g;      # remove any white space

    if ($p =~ /(\d+)\-(\d+)/) {
      $portblock .= "  range $1 $2\n"
    } else {
      $portblock .= "  eq $p\n"
    }
  }
  return $portblock;
}


# generically manipulate junos prefix lists
sub parseAddrBlock {
  my ($addrs) = @_;
  my $block = "";

  my @addrblock = split(/\n/, $addrs);

  foreach my $pref (@addrblock) {
    $pref =~ s/^\s+//g;
    $pref =~ s/\s+$//g;     # cleanup exteraneous whitespace
    $pref =~ s/\;//g;
    next if ($pref eq "");

    $pref   = "  !! $pref" if ( /except/i); # oh what to do about exceptions...?
    $block .= "  $pref\n";
  }
  return $block;
}

# parse the 'then' component of the junos term - there's room for a lot more thought here
sub parseAction {
  my ($actions) = @_;
  my $act = "permit";

  foreach my $opt ($actions) {
    $opt =~ s/^\s+//g;
    $opt =~ s/\s+$//g;     # cleanup exteraneous whitespace
    $opt =~ s/\;//g;

    $act = "deny" if $opt =~ /discard/i;
  }

  return $act;
}




# ---------------------------------------------------------------------
# parseJunosAclTerm - returns a HoH which contain all of the elements
# associated with the junos filter term passed to this.
#
sub parseAclTerm {
  my ($name, $content) = @_;
  my $parse_flag = 0;
  my $acl        = {};                    # initialize anonymous for return value

  while ($parse_flag == 0) {
    my ($pref, $val, $rem) = &get_bracketed($content);
    $parse_flag = 1 if ($val eq "" && $rem eq "");
    $content = $val . $rem;                # does this make sense?

    next if $pref =~ /$name/i;             # skip the filter term name

    # some fields get stranded in a strictly nested parsing model these
    # need to be addressed separately - specifically in the from{}
    # portion of the config
    if ($pref =~ /from/i) {
      # iterate through $val for matches
      # c - continue
      # i - case insensitive
      # g - global
      while ( $val =~ /\b([\-\w]+)\s+(.+)\;/gci ) { # we only want "words" here
        if (exists $term_atoms{$1} ) {
          $acl->{$name}{$1} = $2;
        } else {
          next if $2 =~ /except/;  # junos' "except" is a slick, except for here
          print "!! error: new atom ($1 - $2)\n";
        }
      }
    }

    if ( exists $term_fields{$pref} ) {
      $val =~ s/\{|\}//g;           # strip brackets
      $acl->{$name}{$pref} = $val;
    }
  }
  return $acl;
}


sub get_bracketed {
  my ($str) = @_;

  # seek to beginning of bracket
  return undef unless $str =~ /(\S+)\s+(?={)/gc;

  my $prefix = $1;

  # get everything from the start brace to the matching end brace
  my ($content, $remainder) = extract_bracketed( $str, '{}');

  # no closing brace found
  return undef unless $content;

  return($prefix, $content, $remainder);

}
