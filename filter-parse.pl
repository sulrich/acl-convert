#!/usr/bin/env perl

use strict;
use warnings;
use Text::Balanced qw(extract_multiple extract_delimited extract_bracketed);

# our $braces_re;
# $braces_re = qr{{(?:(?>[^{}]+)|(??{$braces_re}))*}};

# for each element that i want to pull from the data chunk, iterate
# through it again to see if there's anything that's assocaited with a
# nested 'word {' combination.  if there's nothing nested then pull out.

my @terms = (); # stick all of the fw filter terms we run into in here.


my $term_cap  = 0;  # flag for capturing terms
my $term_name = ""; # key for the term
my $term      = {}; # anonymous hash for pushing into @terms

open(ACL, $ARGV[0]) || die "error opening: $ARGV[0]";
while (<ACL>) {
  if (( /term (\w\S+)\s+\{/i ) && ($term_cap == 0)) {
    ## print "-- init: " . $_ . "\n\n";
    # this is the first term we're running into
    $term_cap          = 1; # start capturing
    $term_name         = $1;
    ## print "term name: $term_name\n";

  } elsif (( /term (\w\S+)\s+\{/ ) && ($term_cap == 1)) {
    # we've bumped up against this is the next term for this filter the
    # order of operations is important here
    push @terms, $term;
    $term = {};                            # reset this value
    ## print "nested: " . $_;

    $term_name = $1;
    ## print "term name: $term_name\n";

  }

  if ($term_cap == 1) {
    $term->{$term_name} .= $_;
    ## print "termval: ", $_;
  }
}
push @terms, $term;  # do cleanup
close(ACL);

foreach my $i (0 .. $#terms) {
  foreach my $j (keys %{ $terms[$i] } ) {
    print "term name: $j\n";
    &parseAclTerm($j, $terms[$i]{$j} );
  }

}



sub parseAclTerm () {
  my ($name, $content) = @_;

  my $parse_flag = 0;

  # recurse through these
  while ($parse_flag == 0) {
    my ($pref, $val, $rem) = &get_bracketed($content);
    # print "-- $val\n";

    print "   prefix: $pref\n";
    print "    value: $val\n";
    print "remainder: $rem\n";

    $content = $val;
    $parse_flag = 1 if $val eq "";
  }
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
  #return $content;

}
