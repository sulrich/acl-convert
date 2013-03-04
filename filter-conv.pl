#!/usr/bin/env perl

# steve ulrich <sulrich@<botwerks.org> - 12-feb, 2013
#
# script to convert a junos filter to an ios-xr object-group notation
# style ACL.  i'm sure stuff's broke in here.

use Getopt::Long;
use Text::Balanced qw( extract_bracketed );


my %term_fields = (             # bracketed term fields
                   "destination-address"     => "",
                   "source-address"          => "",
                   "source-prefix-list"      => "", # predefined local object
                   "destination-prefix-list" => "", # predefined local object
                   # "from"                  => "",
                   "then"                    => "",
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
                   "icmp-type"        => "",
                   "fragment-offset"  => "",
                   "policer"          => "",
                  );

my $filter_name = "test"; # can be overridden from the cmd line

my @terms      = (); # all of the fw filter terms go in here.
my $term       = {}; # anonymous hash for pushing into @terms
my $term_cap   = 0;  # flag for capturing terms
my $term_name  = ""; # key for the term
my $acl_inc    = 10; # amount to increment ACL line #s by
my $o_net_objs = "";
my $o_port_obj = "";
my $o_acl      = "";  # the actual output

&GetOptions('f=s' => \$filter_name );

if (!$ARGV[0]) {
  &printUsage;
  exit(1);
}

# standard format for the translated objects is:
#
# -  object-group network ipv4 TERM_NAME-SRC/DST
# -  object-group port TERM_NAME-SRC/DST
#
# junos filter name will result in the same acl name on the IOS XR side

open(ACL, $ARGV[0]) || die "error opening: $ARGV[0]";
while (<ACL>) {
  if (/filter (\w\S+)\s+\{/i) {
    $filter_name = $1;            # we happen to have this in the file,
                                  # use it to name the acl
  }

  if (( /term (\w\S+)\s+\{/i ) && ($term_cap == 0)) {
    # this is the first term we're running into
    $term_cap  = 1;                   # start capturing
    $term_name = $1;

  } elsif (( /term (\w\S+)\s+\{/ ) && ($term_cap == 1)) {
    # we've bumped up against the next term for this filter
    #
    # the order of operations is important here!
    push @terms, $term;
    $term      = {};                  # reset this value
    $term_name = $1;
  }

  $term->{$term_name} .= $_ if ($term_cap == 1) ;
}
push @terms, $term;              # cleanup prior to closing the file.
close(ACL);

# iterate through the various terms we've pulled in and assemble the ACL
# ==============================================================================
foreach my $i (0 .. $#terms) {       # handle terms in order
  foreach my $j (keys %{ $terms[$i] } ) {
    my $acl_struct               = &parseAclTerm( $j, $terms[$i]{$j} );
    my ($netobj, $portobj, $acl) = &processTerm( $j, $acl_struct );

    $o_net_objs  .= $netobj;
    $o_port_objs .= $portobj;
    $o_acl       .= $acl;
  }
}

$o_acl = &number_acl($o_acl); # add line numbers

# iterate through the various terms we've pulled in and assemble the ACL
# ==============================================================================
print $o_net_objs;
print $o_port_objs;
print "ipv4 access-list $filter_name\n" . $o_acl . "!\n";



# processTerm - iterates through the ACL structure passed to it and
# assembles the associated objects which are concatenated by the caller
# into the larger configuration assembly.
#
# this will need more attention as more capabilities in terms of
# translation are added.
sub processTerm {
  my ($aclname, $aclref) = @_;

  my ($netobj, $portobj, $acl,
      $src_block, $src_ports,  # *_block - used to generate  net-object strings
      $dst_block, $dst_ports,  # *_port - used to generate net-object
      $action, $counter) = "";

  my @protocols      = ();
  my $netobj_prefix  = "object-group network ipv4 ";
  my $portobj_prefix = "object-group port ";
  my $snet_name     = "$aclname-SRC";
  my $dnet_name     = "$aclname-DST";
  my $sport_name    = "$aclname-SRC_PORTS";
  my $dport_name    = "$aclname-DST_PORTS";
  my $flag          = "";

  foreach my $field (keys %{ $aclref->{$aclname} }  ) {

    if ($field  =~ /source-address/i ) {
      $src_block = &parseAddrBlock( $aclref->{$aclname}->{$field} );
      $netobj .= $netobj_prefix . "$snet_name\n" . $src_block . "!\n";
    }

    elsif ($field  =~ /destination-address/i ) {
      $dst_block = &parseAddrBlock( $aclref->{$aclname}->{$field} );
      $netobj .= $netobj_prefix . "$dnet_name\n" . $dst_block . "!\n";
    }

    elsif ($field  =~ /protocol/i ) {
     @protocols = &parseProtocol( $aclref->{$aclname}->{$field} );
    }

    elsif ($field  =~ /source-port/i )         {
      $src_ports = &parsePortBlock( $aclref->{$aclname}->{$field} );
      $portobj .= $portobj_prefix . $sport_name . "\n" . $src_ports . "!\n";
    }

    elsif ($field  =~ /destination-port/i )    {
      $dst_ports = &parsePortBlock( $aclref->{$aclname}->{$field} );
      $portobj .= $portobj_prefix . $dport_name . "\n" . $dst_ports . "!\n";
    }
    elsif ($field  =~ /then/i ) {
      $action = &parseAction( $aclref->{$aclname}->{$field} );
    }
    elsif ($field  =~ /tcp-established/i ) {
      $flag .= "established";
    }


  }

  my ($snet_str, $sport_str,       # (net|port)-string - for output
      $dnet_str, $dport_str) = "";

  # if we're this far and there's no src/dst addresses set - permit all!
  # and assume that the protocol stuff is to be the match criteria.
  if ($src_block eq "") {
    $snet_str = "any";
  } else {
    $snet_str = "net-group $snet_name"
  }

  if ($dst_block eq "") {
    $dnet_str = "any";
  } else {
    $dnet_str = "net-group $dnet_name"
  }

  # if there's no protocol specified when we process the term, then
  # we're just creating a standard ACL.  if there's a protocol specified
  # then we need to build out the extended ACL syntax.
  if (@protocols >= 1) {
    foreach my $prot (@protocols) {
      # all hail tcp || udp
      if ($prot =~ /(tcp|udp)/i) {
        $sport_str = "port-group $sport_name" if ($src_ports ne "");
        $dport_str = "port-group $dport_name" if ($dst_ports ne "");

        $acl .= "$action $prot $snet_str $sport_str $dnet_str $dport_str $flag";
        $acl =~ s/\s+/ /g;            # eliminate 2+ spaces in the output
        $acl .= "\n";

      } elsif ($prot =~ /icmp/i) {
        # process icmp-message types
        my @ilist = &parseIcmpTypes( $aclref->{$aclname}->{'icmp-type'} );
        foreach my $i (@ilist) {
          $acl .= "$action $prot $snet_str $dnet_str $i\n";
          # skipping the scrub of the acl line since it's tightly formed
        }
      }
    }
  } else {
    $acl .= "$action $snet_str $dnet_str $flag";
    $acl =~ s/\s+/ /g;            # eliminate 2+ spaces in the output
    $acl .= "\n";
  }

  return ($netobj, $portobj, $acl);
}


# parseProtocol - returns an array of protocols for the caller to
# iterate through when building the acl.
sub parseProtocol {
  my ($str) = @_;
  $str =~ s/\[|\]|\;//g; # rip off the chrome
  $str =~ s/^\s+//g;
  $str =~ s/\s+$//g;     # cleanup white space

  my @protocols = split(/\s+/, $str);
  return @protocols;
}

# parsePortBlock - returns the body of a port object-group creates range
# and eq statements as necessary.
sub parsePortBlock {
  my ($str) = @_;
  $str =~ s/\[|\]|\;//g; # rip off the chrome
  $str =~ s/^\s+//g;
  $str =~ s/\s+$//g;     # cleanup white space

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

# parseIcmpTypes - returns an array of icmp-types to generate the ICMP
# specific list ACL list
sub parseIcmpTypes {
  my ($str) = @_;
  $str =~ s/\[|\]|\;//g; # rip off the chrome
  $str =~ s/^\s+//g;
  $str =~ s/\s+$//g;     # cleanup white space

  my @icmptypes = split(/\s+/, $str);

  my @icmplist = ();
  foreach my $p (@icmptypes) {
    if ($p =~ /(\d+)\-(\d+)/) {
      # $portblock .= "  range $1 $2\n";
      foreach my $i ( $1 .. $2) { push @icmplist, $i; }
    } else {
      push @icmplist, $p;
    }
  }
  return @icmplist;
}


# parseAddrBlock - returns the body of a network object-group statement.
# it doesn't do anything particularly clever wrt the juniper 'except'
# statements.
#
# XXX - what to do about the except operations?  does it make sense to
# parse these and optimize them within the context of the network
# object-group?
sub parseAddrBlock {
  my ($addrs) = @_;
  my $block = "";

  my @addrblock = split(/\n/, $addrs);

  foreach my $pref (@addrblock) {
    $pref =~ s/^\s+//g;
    $pref =~ s/\s+$//g;     # cleanup extraneous white space
    $pref =~ s/\;//g;
    next if ($pref eq "");

    $pref   = "!! $pref" if ( $pref =~ /except/i ); # oh what to do about exceptions...?
    $block .= "  $pref\n";
  }
  return $block;
}

# parse the 'then' component of the junos term - there's room for a lot
# more thought here - right now it just tells us whether to permit/deny
# the statement.
#
# XXX - i need to add more handling for counters, forwarding class, etc.
sub parseAction {
  my ($actions) = @_;
  my $act = "permit";

  foreach my $opt ($actions) {
    $opt =~ s/^\s+//g;
    $opt =~ s/\s+$//g;     # cleanup extraneous white space
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
          print "!! ERROR: new atom ($1 - $2)\n";
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

# get_bracketed - this is mostly wrapper around the Text::Balanced stuff
# to facilitate recursing through the ACL term contents.
sub get_bracketed {
  my ($str) = @_;
  my ($prefix, $content, $remainder) = "";
  # seek to beginning of bracket
  return undef unless $str =~ /(\S+)\s+(?={)/gc;

  $prefix = $1;

  # get everything from the start brace to the matching end brace
  ($content, $remainder) = extract_bracketed( $str, '{}');

  # no closing brace found
  return undef unless $content;

  return($prefix, $content, $remainder);

}

# stick line numbers on the front of the ACL.
sub number_acl {
  my ($acl) = @_;
  my $o = "";
  my $lnum = $acl_inc;

  my @lines = split (/\n/, $acl);
  foreach my $l (@lines) {
    $o .= "  $lnum $l\n";
    $lnum = $lnum + $acl_inc
  }
  return $o;
};

# dump a usage message to the user
sub printUsage {
  my ($mesg) = @_;

  print STDERR <<EOF;

filter-conv.pl [-f filter_name] input_file_path

options
 -f specify a filter name

error:
 $mesg
EOF

  return;
}
