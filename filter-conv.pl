#!/usr/bin/env perl

# steve ulrich <sulrich@<botwerks.org> - 12-feb, 2013
#
# script to convert a junos filter to an ios-xr object-group notation
# style ACL.  i'm sure stuff's broke in here.

use Getopt::Long;
use Text::Balanced qw( extract_bracketed );


my %term_fields = (             # bracketed term fields
                   "destination-address"     => "",
                   "destination-prefix-list" => "", # predefined local object
                   "from"                    => "",
                   "source-address"          => "",
                   "source-prefix-list"      => "", # predefined local object
                   "then"                    => "",
                  );

my %term_atoms = (              # these are field terms we attempt to do
                                # something reasonable with
                  "accept"                    => "",
                  "destination-port"          => "",
                  "icmp-type"                 => "",
                  "protocol"                  => "",
                  "source-port"               => "",
                  "tcp-established"           => "",
                  # "count"                     => "",
                  # "first-fragment"            => "",
                  # "forwarding-class"          => "",
                  # "fragment-offset"           => "",
                  # "is-fragment"               => "",
                  # "packet-length"             => "",
                  # "policer"                   => "",
                                # the following are local objects
                  # "configured-neighbors-only" => "",
                  # "ipv4-local-interfaces"     => "",
                 );

my $filter_name = "test";       # can be overridden from the cmd line

my @terms      = ();            # all of the fw filter terms go in here.
my $term       = {};            # anonymous hash for pushing into @terms
my $term_cap   = 0;             # flag for capturing terms
my $term_name  = "";            # key for the term
my $acl_inc    = 10;            # amount to increment ACL line #s by
my $o_net_objs = "";
my $o_port_obj = "";
my $o_acl      = "";            # the actual output

&GetOptions('f=s' => \$filter_name );

if (!$ARGV[0]) {
  &printUsage;
  exit(1);
}

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
    $term      = {};            # reset this value
    $term_name = $1;
  }

  $term->{$term_name} .= $_ if ($term_cap == 1) ;
}
push @terms, $term;             # cleanup prior to closing the file.
close(ACL);

# iterate through the various terms we've pulled in and assemble the ACL
# ==============================================================================
foreach my $i (0 .. $#terms) {       # handle terms in order
  foreach my $j (keys %{ $terms[$i] } ) {
    # $acl_struct (HoH with the parsed fields in keys)
    my $acl_struct               = &parseAclTerm( $j, $terms[$i]{$j} );
    my ($netobj, $portobj, $acl) = &processTerm( $j, $acl_struct );

    $o_net_objs  .= $netobj;
    $o_port_objs .= $portobj;
    $o_acl       .= $acl;
  }
}

$o_acl = &number_acl($o_acl, $acl_inc);   # add line numbers to the output

# actually output the ACL
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

  my ($netobj, $portobj) = "";

  my $netobj_prefix  = "object-group network ipv4 ";
  my $portobj_prefix = "object-group port ";

  my %term = (
              sport_name => "$aclname-SRC_PORTS",
              dport_name => "$aclname-DST_PORTS",
              snet_name  => "$aclname-SRC",
              snet_xname => "$aclname-EXCPT",
              dnet_name  => "$aclname-DST",
              dnet_xname => "$aclname-EXCPT",
              action     => "",
              flag       => "",
             );

  foreach my $field (keys %{ $aclref->{$aclname} }  ) {

    if ( $field  =~ /source-address/i ) {
      ($term{'src_block'}, $term{'src_excpt'}) = &parseAddrBlock( $aclref->{$aclname}->{$field} );
      $netobj .= $netobj_prefix . "$term{'snet_name'}\n" . $term{'src_block'} . "!\n";
      if ($term{'src_excpt'} ne "") {
        $netobj .= $netobj_prefix . "$term{'snet_xname'}\n" . $term{'src_excpt'} . "!\n";
      }
    }
    elsif ($field  =~ /destination-address/i ) {
      ($term{'dst_block'}, $term{'dst_excpt'}) = &parseAddrBlock( $aclref->{$aclname}->{$field} );
      $netobj .= $netobj_prefix . "$term{'dnet_name'}\n" . $term{'dst_block'} . "!\n";
      if ($term{'dst_excpt'} ne "") {
        $netobj .= $netobj_prefix . "$term{'dnet_xname'}\n" . $term{'dst_excpt'} . "!\n";
      }
    }
    elsif ($field  =~ /source-port/i )         {
      $term{'src_ports'} = &parsePortBlock( $aclref->{$aclname}->{$field} );
      $portobj .= $portobj_prefix . $term{'sport_name'} . "\n" . $term{'src_ports'} . "!\n";
    }
    elsif ($field  =~ /destination-port/i )    {
      $term{'dst_ports'} = &parsePortBlock( $aclref->{$aclname}->{$field} );
      $portobj .= $portobj_prefix . $term{'dport_name'} . "\n" . $term{'dst_ports'} . "!\n";
    }
    elsif ($field  =~ /protocol/i ) {
      my @protocols = &parseProtocol( $aclref->{$aclname}->{$field} );
      $term{'protocols'} = [ @protocols ];
    }
    elsif ($field  =~ /then/i ) {
      $term{'action'} = &parseAction( $aclref->{$aclname}->{$field} );
    }
    elsif ($field  =~ /tcp-established/i ) {
      $term{'flag'} .= "established";
    }
  }

  my $ace = generateACE(%term);
  return ($netobj, $portobj, $ace);
}


sub generateACE {
  my (%te) = @_;                # hash of all of the ACE elements

  my $ace = "";

  # if we're this far and there's no src/dst addresses set - permit all!
  # and assume that the protocol stuff is to be the match criteria.
  if ($te{'src_block'} eq "") {
    $te{snet_str} = "any";
  } else { $te{snet_str} = "net-group $te{snet_name}"; }

  if ($te{'dst_block'} eq "") {
    $te{dnet_str} = "any";
  } else { $te{dnet_str} = "net-group $te{dnet_name}"; }

  # step through the exception handling options
  if ( ($te{src_excpt} ne "") && ($te{dst_excpt} ne "") ) {
    # use exception src_addrs and dest_addrs
    $ace .= "REMARK -- START :: TERM CONTAINING EXCEPTION PROCESSING ---\n";
    $ace .= generateAceProtocols(\%te,
                                 "net-group $te{snet_xname}",
                                 "net-group $te{dnet_xname}",
                                 &invertAction($te{action}));
    $ace .= generateAceProtocols(\%te, $te{snet_str}, $te{dnet_str}, $te{action});
    $ace .= "REMARK -- END :: TERM CONTAINING EXCEPTION PROCESSING ---\n";
  }
  elsif ( ($te{src_excpt} ne "") && ($te{dst_excpt} eq "")) {
    # use exception src_addrs and term dest_addrs
    $ace .= "REMARK -- START :: TERM CONTAINING EXCEPTION PROCESSING ---\n";
    $ace .= generateAceProtocols(\%te,
                                 "net-group $te{snet_xname}",
                                 $te{dnet_str},
                                 &invertAction($te{action}));
    $ace .= generateAceProtocols(\%te, $te{snet_str}, $te{dnet_str}, $te{action});
    $ace .= "REMARK -- END :: TERM CONTAINING EXCEPTION PROCESSING ---\n";
  }
  elsif ( ($te{src_excpt} eq "") && ($te{dst_excpt} ne "")) {
    # use term src_addrs and exception destination
    $ace .= "REMARK -- START :: TERM CONTAINING EXCEPTION PROCESSING ---\n";
    $ace .= generateAceProtocols(\%te,
                                 $te{snet_str},
                                 "net-group $te{dnet_xname}",
                                 &invertAction($te{action}));
    $ace .= generateAceProtocols(\%te, $te{snet_str}, $te{dnet_str}, $te{action});
    $ace .= "REMARK -- END :: TERM CONTAINING EXCEPTION PROCESSING ---\n";
  }
  else {
    # there are no exception addresses to handle
    $ace .= generateAceProtocols(\%te, $te{snet_str}, $te{dnet_str}, $te{action});
  }

  return $ace;
}

sub generateAceProtocols {
  my ($te, $snet_str, $dnet_str, $action) = @_;
  my $ace = "";

  # if there's no protocol specified when we process the term, then
  # we're just creating a standard ACL.  if there's a protocol specified
  # then we need to build out the extended ACL syntax.
  if ( @{ $te->{protocols} } >= 1 ) {
    foreach my $prot ( @{ $te->{'protocols'} } ) {
      if ($prot =~ /(tcp|udp)/i) {
        # all hail tcp || udp
        $sport_str = "port-group $te->{'sport_name'}" if ($te->{'src_ports'} ne "");
        $dport_str = "port-group $te->{'dport_name'}" if ($te->{'dst_ports'} ne "");

        $ace .= "$action $prot $snet_str $sport_str $dnet_str $dport_str $te{flag}";
        $ace =~ s/\s+/ /g;      # eliminate 2+ spaces in the output
        $ace .= "\n";

      } elsif ($prot =~ /icmp/i) {
        # process icmp-message types
        my @ilist = &parseIcmpTypes( $aclref->{$aclname}->{'icmp-type'} );
        foreach my $i (@ilist) {
          $ace .= "$action $prot $snet_str $dnet_str $i\n";
          # skipping the scrub of the acl line since it's tightly formed
        }
      }
    }
  } else {
    $ace .= "$action $snet_str $dnet_str $te{flag}";
    $ace =~ s/\s+/ /g;          # eliminate 2+ spaces in the output
    $ace .= "\n";
  }

  return $ace;
}


# parseProtocol - returns an array of protocols for the caller to
# iterate through when building the acl.
sub parseProtocol {
  my ($str) = @_;
  $str =~ s/\[|\]|\;//g;        # rip off the chrome
  $str =~ s/^\s+//g;
  $str =~ s/\s+$//g;            # cleanup white space

  my @protocols = split(/\s+/, $str);
  return @protocols;
}

# parsePortBlock - returns the body of a port object-group creates range
# and eq statements as necessary.
sub parsePortBlock {
  my ($str) = @_;
  $str =~ s/\[|\]|\;//g;        # rip off the chrome
  $str =~ s/^\s+//g;
  $str =~ s/\s+$//g;            # cleanup white space

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
  $str =~ s/\[|\]|\;//g;        # rip off the chrome
  $str =~ s/^\s+//g;
  $str =~ s/\s+$//g;            # cleanup white space

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
sub parseAddrBlock {
  my ($addrs) = @_;
  my ($block, $except) = "";

  my @addrblock = split(/\n/, $addrs);

  foreach my $pref (@addrblock) {
    $pref =~ s/^\s+//g;
    $pref =~ s/\s+$//g;         # cleanup extraneous white space
    $pref =~ s/\;//g;
    next if ($pref eq "");

    if ($pref !~ /except/) {
      $block .= "  $pref\n";
    } else {
      $pref   =~ s/except//g;
      $except .= "  $pref\n";
    }
  }
  return($block, $except);
}

# parse the 'then' component of the junos term - there's room for a lot
# more thought here - right now it just tells us whether to permit/deny
# the statement.
#
# XXX - i need to add more handling for counters, forwarding class, etc.
sub parseAction {
  my ($actions) = @_;
  my $act = "permit";           # seems like a reasonable place to start

  foreach my $opt ($actions) {
    $opt =~ s/^\s+//g;
    $opt =~ s/\s+$//g;          # cleanup extraneous white space
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

      foreach my $l (split /\n/, $val) {
        next if $l =~ /\d{1,3}\.\d{1,3}/;        # skip ip addresses
        if ( $l =~ /\b([\-\w]+)\s+(.+)\;/gci ) { # we only want "words" here
          if (exists $term_atoms{$1} ) {
            $acl->{$name}{$1} = $2;
          } else {
            print "!! ERROR: unrecognized atom ($1: $2) - term: $name\n";
          }
        }
        elsif ( $l =~ /\b([\-\w]+)\;/gci ) {     # single elements
          if (exists $term_atoms{$1} ) {
            $acl->{$name}{$1} = "";
          } else {
            print "!! ERROR: unrecognized atom ($1) - term: $name\n";
          }
        }
      }
    }  # end of parsing from {} terms

    if ( exists $term_fields{$pref} ) {
      $val =~ s/\{|\}//g;       # strip brackets
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

sub invertAction {
  my ($action) = @_;

  return "deny"   if ($action =~ /permit/i);
  return "permit" if ($action =~ /deny/i  );
}


# stick line numbers on the front of the ACL.
sub number_acl {
  my ($acl, $inc) = @_;
  my $o = "";
  my $lnum = $inc;

  my @lines = split (/\n/, $acl);
  foreach my $l (@lines) {
    $o .= "  $lnum $l\n";
    $lnum = $lnum + $inc
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
