#!/usr/bin/env perl

use strict;
use warnings;
use Data::Dumper;
use Text::Balanced qw(extract_multiple extract_delimited extract_bracketed);


my %term_fields = (
                   "destination-address"  => "",
                   "source-address"       => "",
                   # "from"                 => "",
                   "then"                 => "",
                  );

my %term_atoms = (
                   "protocol"             => "",
                   "destination-port"     => "",
                   "source-port"          => "",
                   "forwarding-class"     => "",
                   "count"                => "",
                   "accept"               => "",
                   "tcp-established"      => "",
                  );


my @terms = (); # stick all of the fw filter terms we run into in here.

my $term_cap  = 0;  # flag for capturing terms
my $term_name = ""; # key for the term
my $term      = {}; # anonymous hash for pushing into @terms

open(ACL, $ARGV[0]) || die "error opening: $ARGV[0]";
while (<ACL>) {
  if (( /term (\w\S+)\s+\{/i ) && ($term_cap == 0)) {
    # this is the first term we're running into
    $term_cap          = 1; # start capturing
    $term_name         = $1;

  } elsif (( /term (\w\S+)\s+\{/ ) && ($term_cap == 1)) {
    # we've bumped up against this is the next term for this filter the
    # order of operations is important here
    push @terms, $term;
    $term = {};                            # reset this value

    $term_name = $1;
  }

  if ($term_cap == 1) {
    $term->{$term_name} .= $_;
  }
}
push @terms, $term;              # do cleanup prior to closing the file.
close(ACL);



foreach my $i (0 .. $#terms) {  # handle in order
  foreach my $j (keys %{ $terms[$i] } ) {
    print "term name: $j\n";
    my $acl = &parseAclTerm($j, $terms[$i]{$j} );
    print Dumper $acl;
  }

}

sub parseAclTerm () {
  my ($name, $content) = @_;
  my $parse_flag = 0;

  my $acl = {};    # initialize anonymous for return value


  while ($parse_flag == 0) {
    my ($pref, $val, $rem) = &get_bracketed($content);
    $parse_flag = 1 if ($val eq "" && $rem eq "");
    $content = $val . $rem; # does this make sense?

    next if $pref =~ /$name/i; # skip the filter term name
    # next if $pref =~ /from/i;  #

    # some fields get stranded in a strictly nested parsing model
    # break these out separately - specifically in the from{} portion of the config
    if ($pref =~ /from/i) {
      # iterate through $val for matches
      # c - continue
      # i - case insensitive
      # g - global
      while ( $val =~ /\b([\-\w]+)\s+(.+)\;/gci ) {
        if (exists $term_atoms{$1} ) {
          $acl->{$name}{$1} = $2;
        } else {
          next if $2 =~ /except/;  # junos' "except" is a slick, except for here
          print "error: new atom ($1 - $2)\n";
        }
      }
    }

    if ( exists $term_fields{$pref} ) {
      $val =~ s/\{|\}//g;
      $acl->{$name}{$pref} = $val;
    }
  }

  return $acl;
}


sub get_bracketed {
  my ($str) = @_;

  # seek to beginning of bracket
  return undef unless $str =~ /(\S+)\s+(?={)/gc;

  # store the prefix
  my $prefix = $1;
  #print "prefix: $prefix\n";

  # get everything from the start brace to the matching end brace
  my ($content, $remainder) = extract_bracketed( $str, '{}');
  #print "  content: $content\n";
  #print "remainder: $remainder\n";

  # no closing brace found
  return undef unless $content;

  # return the whole match
  return($prefix, $content, $remainder);

}
