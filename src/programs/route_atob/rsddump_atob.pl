#!/bin/perl
#
# Convert RSd style (similar to GateD) ASCII table dump to binary
# MRT RIB dump. Once converted, the binary table can be loaded by BGPSim and
# MRTd for testing. Useful for testing with Mae-East routing table for example.
# Author -- C. Labovitz, 7/21/98
#

require "getopts.pl";

# GLOBAL Variables
$LEN = 0;
$BUF = "";
$USAGE = "rsddump_atob.pl -o binary_output_file";
$SEQ_NUM = 0;

&Getopts("i:o:v");
if(defined $opt_o) {
    $OUTPUT = $opt_o;
}
if(defined $opt_i) {
    $INPUT = $opt_i;
}
if(defined $opt_v) {
    $DEBUG = 1;
}

if (($INPUT eq "") || ($OUTPUT eq "")) {
    print "Usage: $USAGE\n";
    exit;
}


open (OUT, "> $OUTPUT") || die "Could not open $OUTPUT\n";
open (INPUT, $INPUT) || die "Could not open $INPUT\n";

while (<INPUT>) {
  #print $_;
  if (/^View\[(\d+)\]=([\d\.]+)/) {
    # do nothing 
  }
  if (/^\s*\n/) {
    $in_entry = 0; 
    @attr = ();
    next;
  }
  if (/^D\[([\d\.\/]+)\]:\s+r=(\d+).*/) {
    $prefix = $1;
	    
    $refcount = $2;
    if ($refcount == 0) {
      $in_entry = 0; 
      next;
    }
    if ($prefix eq "0.0.0.0/0.0.0.0") {next;}
    if ($prefix eq "127.0.0.1/255.255.255.255") {next;}


    $prefix =~ /^([\d\.]+)\/([\d\.]+)/;
    @p = split (/\./, $1);
    $mask = &bitlen ($2);	
    $p3 = $p[3]+ 0;
    $p2 = $p[2]+ 0;
    $p1 = $p[1]+ 0;
    $p0 = $p[0]+ 0;
    $in_entry = 1;
    next;
  }
  if ($in_entry == 1) {
    if (/^V\[(\d+)\]:\s+R\[BGP\/([\d\.]+)\]/) {
      $view = $1;
      $peer = $2;
    }
    if (/R\[BGP\/([\d\.]+)\]:\s+N=([\d\.]+)/) {
      @attr = ();
      $peer = $1;
      $next = $2;
      $_ =~ /A=\(\d+\)\s([\d+\s\[\]]+)(\w+)/;
      $aspath = $1;
      $origin = $2;
      $_ =~ /\sR=(\d+)\sA=/;
      $peeras = $1;
      @a = split (/\s+/, $aspath);
      $o = $a[$#aspath ];
      @a = split (/[\s\[\]]+/, $aspath);
      push (attr, "origin $origin");
      push (attr, "nexthop $next");
      push (attr, "aspath $aspath");
      &process;
    }
  }
}



sub process {
  $time = time;
  
  if ($LEN > 1000) {
    #print "New packet ($LEN)\n";
    print_mrt_header ($time, $LEN);
    print OUT $BUF;
    $BUF = "";
    $LEN = 0;
  }

  if ($BUF eq "") {
    $BUF .= pack ("S", 23); # view
    $BUF .= pack ("S", $SEQ_NUM++); # view
    $LEN +=4;
  }

  #print "$prefix [@p]\n"; 

  ($attr_len, $ATTR) = &build_attr;
  
  $BUF .= pack ("CCCC", $p[0], $p[1], $p[3], $p[3]);  # prefix
  $BUF .= pack ("C", $mask);  # mask
  $BUF .= pack ("C", 1);   # status
  $BUF .= pack ("N", $time); # time originated
  $BUF .= pack ("N", 0); # peer ip
  $BUF .= pack ("S", 0); # peer AS
  $BUF .= pack ("S", $attr_len);
  $BUF .= $ATTR;
  $LEN += 12 + $attr_len;
}



sub print_mrt_header {
  local ($time, $length) = @_;
  $type = 12;    #Routing Table Dump
  $subtype = 1; #update

  print OUT pack ("NnnN", $time, $type, $subtype, $length);

}



sub build_attr {
  local ($OUT);

  $OUT = "";

  #path attributes
  $totalattrib_length = 0;
    
  # path attributes 
  foreach $attr (@attr) {
    ($type, @value) = split (/\s+/, $attr);
    if ($type eq "origin") {
      #attr-flag | attr_type_code | length
      $OUT .= pack ("C1C1C1", 0x40, 1, 1); 
      $OUT .= pack ("C1", $ORIGIN_HASH[$value[0]]);      # origin
      $totalattrib_length += 4;
    }
    elsif ($type eq "aspath") {
      $OUT .= pack ("C1C1", 0x40, 2); #attr-flag! attr_type_code
      $totalattrib_length += 2;
      $length = 0;

      &break_into_sets;

      foreach $i (0..$nset) {
	@s = split (/\s+/, $sets[$i]);
	$length += 2 + 2* $#s;
      }
      $OUT .= pack ("C1", $length);
      $totalattrib_length += 1;
      #print "$prefix $length $aspath\n"; exit;

      # okay, now encode each set/sequence
      foreach $i (0..$nset) {
	@s = split (/\s+/, $sets[$i]);
	$t = shift (@s);
	if ($t eq "seq") {
	  $OUT .=  pack ("C1", 2);      # sequence
	  $totalattrib_length += 1;
	}
	else {
	  $OUT .=  pack ("C1", 1);      # set
	  $totalattrib_length += 1;
	}
	$OUT .=  pack ("C1", ($#s + 1));  #num as's
	$totalattrib_length += 1;
	foreach $as (@s) {  
	  $OUT .=  pack ("S", $as);
	  $totalattrib_length += 2;
	}
      }
    }
    elsif ($type eq "nexthop") {
      @addr = split (/\./, $value[0]);
      #attr-flag | attr_type_code | length
      $OUT .= pack ("C1C1C1", 0x40, 3, 4);
      $OUT .= pack ("C4", @addr);
      $totalattrib_length += 7;
    }
    elsif ($type eq "multiexit") {
      @addr = split (/\./, $value[0]);
      #attr-flag | attr_type_code | length
      $OUT .= pack ("C1C1C1", 0x80, 4, 4);
      $OUT .= pack ("N", $value[0]);
      $totalattrib_length += 7;
    }
    elsif ($type eq "atomic_aggregate") {
      #attr-flag | attr_type_code | length
      $OUT .= pack ("C1C1C1", 0x40, 6, 0);
      $totalattrib_length += 3;
    }
    elsif ($type eq "aggregator") { 
      @addr = split (/\./, $value[1]);
      #attr-flag | attr_type_code | length
      $OUT .= pack ("C1C1C1", 0xc0, 7, 6);
      $OUT .= pack ("SC4", $value[0], @addr);
      $totalattrib_length += 9;
    }
  }

  return ($totalattrib_length, $OUT);
}


# someday I will learn how to do integer division in perl... (sigh)
sub bytes {
    local ($length) = @_;

    if ($length <= 8) { return (1);}
    if ($length <= 16) {return (2);}
    if ($length <= 24) {return (3);}
    
    return (4);
}


sub bitlen {
    local ($mask) = @_;

    $total = 0;
    @byte = split (/\./, $mask);


    foreach $byte (@byte) {
	if ($byte == 255) {$total += 8; next;}



	$vector = pack ("C", $byte);
	$bits = unpack ("B*", $vector);
	@bits = split (//, unpack ("B*", $vector));
	foreach $bit (@bits) {
	    if ($bit == 1) {$total++;}
	    else {last;}
	}
    }

    return $total;
}




sub break_into_sets {
  # break up aspath into sequences and sets
  # store information in global $nset, and @sets
  $nset = 0; @sets = (); $lastelement = "";
  $sets[0] = "seq ";
  foreach $element (@value) {
    if ($element =~ /\d+/) {
      if ($lastelement eq "]") {
	$nset++;
	$sets[$nset] = "seq $element ";
      }
      else {$sets[$nset] .= "$element ";}
    }
    elsif ($element eq "[") {
      if ($lastelement ne "") {$nset++;}
      $sets[$nset] = "set ";
    }
    elsif ($element eq "]") {;} # noop
    else {
      print "unknown $element\n";
    }
    $lastelement = $element;
  }
}
