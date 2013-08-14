#!/usr/local/bin/perl
#
# $Id: route_atob.pl,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
#
# Name:    route_atob.pl
# Author:  Craig Labovitz (Merit Network, Inc.) <labovit@merit.edu>
#  A perl version of route_atob. Convert ASCII description of BPP packets
#  into MRT binary BGP messages.
#
# TODO
# * Should be able to produce both announce and withdraws in same packet
# * Support for DPA and communitities
#
# CHANGES:
#   11/21/96  Fixed bug where 0 used as attr flag (labovit). Reported by
#     dward@ascend.com
#   11/21/96  Added support for aspath sets and segments. Even null set.
#

require "timelocal.pl";
require "getopts.pl";

my $USAGE;
my $INPUT;
my $OUTPUT;
my $DEBUG;

$USAGE = "route_atob.pl -i ascii_input_file -o binary_output_file";
%ORIGIN_HASH  = ('Incomplete', 2, 'EGP', 1, 'IGP', 0);

# options
&Getopts("i:f:o:v");
if(defined $opt_i) {
    $INPUT = $opt_i;
}
if(defined $opt_f) {
    $INPUT = $opt_f;
}
if(defined $opt_o) {
    $OUTPUT = $opt_o;
}
if(defined $opt_v) {
    $DEBUG = 1;
}

if (($INPUT eq "") || ($OUTPUT eq "")) {
    print "Usage: $USAGE\n";
    exit;
}

# handle special stdin and stdout cases
if ($INPUT eq "stdin") {$INPUT = "-";}
if ($OUTPUT eq "stdout") {
    open (OUT, ">-");
}
else {
    open (OUT, "> $OUTPUT") || die "Could not open $OUTPUT : $! \n";
}


&read_input ($INPUT);
close (OUT);

sub read_input {
    local ($inputfile) = @_;
    my $month, $mday, $year, $hour, $min, $sec, $src, $dst;

    if (open (INPUT, $inputfile) < 1) {
	print "Could not open $inputfile\n";
	return;
    }

    $line = 0;
    while (<INPUT>) {
	$line++;
	#print $_;
	if (/TIME:\s+(\d+)\/(\d+)\/(\d+)\s+(\d+):(\d+):(\d+)/i) {
	    $month = $1;
	    $mday = $2;
	    $year = $3;
	    $hour = $4;
	    $min = $5;
	    $sec = $6;
	}

	elsif (/\TYPE:\sBGP\/UPDATE/i) {}
	elsif (/ORIGIN:\s+(\w+)/i) {$attr[$nattr++] = "origin $1";}
	# for simplicity, make sure spaces around sets in aspath
	elsif (/ASPATH:\s+([\d\s\[\]]+)/i) {$path = $1; $path =~ s/\[/ \[  /g;
					    $path =~ s/\]/ \]  /g;
					    $attr[$nattr++] = "aspath $path";}
	elsif (/WITHDRAW/i) {$unreachable = 1;}
	elsif (/ANNOUNCE/i) {$unreachable = 0;}
	elsif (/^TO:/) {}
	elsif (/^\s+([\d\.\/]+).*/) {
	    $routes .= "$1 ";
	}
	elsif (/NEXT_HOP:\s+([\d\.]+)/) {$attr[$nattr++] = "nexthop $1";}
	elsif (/MULTI_EXIT_DISC:\s(\d+).*/) {$attr[$nattr++] = "multiexit $1";}
	elsif (/ATOMIC_AGGREGATE.*/) {$attr[$nattr++] = "atomic_aggregate";}
	elsif (/AGGREGATOR:\s([\w\s\d\.]+).*/) {$attr[$nattr++] = "aggregator $1";}
	elsif ((/^\s*\n/) && ($routes ne "")) {
	    if ($unreachable == 1) { 
		&build_packet_withdraw ($month, $mday, $year, $hour, $min, $sec);
	    }
	    else {
		&build_packet_announce ($month, $mday, $year, $hour, $min, $sec);
	    }
	    &reset_bgp_recv;
	}	    
	elsif (/\s*\n/) {}
	else {print "error\n$_"; }
    }
}

sub reset_bgp_recv {
    $in_bgp_recv = 0;
    $src = "";
    $dst = "";
    $unreachable = 0;
    $routes = "";
    $msg = "";
    @attr = "";
    $nattr = 0;
}


sub build_packet_withdraw {
    local ($month, $mday, $year, $hour, $min, $sec) = @_;
    
    $time = &gettime ($month, $mday, $year, $hour, $min, $sec);
    $length = 0;  #to be determined
    $totalwithbyte;

    $routes =~ s/[,\s\n]+/ /g;
    @routes = split (/\s+/, $routes);

    $totalwithbyte = 0;
    $withdata = "";
    $count = 0;

    # withdraw size calculations
    foreach $route (@routes) {
	($prefix, $length) = split (/\//, $route);
	$byte = &bytes ($length);
	$totalwithbyte += ($byte + 1);
    }

    $length = 12 + 2 + $totalwithbyte + 2;

    # MRT MSG header
    &print_mrt_header ($time, $length, $src, $dst);

    # withdraw routes
    if ($DEBUG) {print OUT pack ("S1", $totalwithbyte);}
    print OUT pack ("S1", $totalwithbyte);
     foreach $route (@routes) {
	($prefix, $length) = split (/\//, $route);
	@prefix = split (/\./, $prefix);
	$byte = &bytes ($length);
	print OUT pack ("C1C$byte", $length, @prefix);
    }

    # total path attributes field
    print OUT pack ('C2', 0);
}


sub print_mrt_header {
    local ($time, $length, $src, $dst) = @_;
    $type = 5;    #BGP
    $subtype = 1; #update

    @src = split (/\./, $src);
    @dst = split (/\./, $dst);
    print OUT pack ("NnnN", $time, $type, $subtype, $length);
    print OUT pack ('SC4', 0, @src);
    print OUT pack ('SC4', 0, @dst);
    #print "time = $time\n";
}



sub build_packet_announce {
    local ($month, $mday, $year, $hour, $min, $sec) = @_;

    $time = &gettime ($month, $mday, $year, $hour, $min, $sec);
    $length = 0;  #to be determined
    $nlri_byte = 0;

    $routes =~ s/[,\s\n]+/ /g;
    @routes = split (/\s+/, $routes);

    #path attributes
    $totalattrib_length = 0;

    foreach $attr (@attr) {
	($type, @value) = split (/\s+/, $attr);
	if ($type eq "origin") {
	    $totalattrib_length += 2; #attr-flag! attr_type_code
	    $totalattrib_length += 1; #length
	    $totalattrib_length += 1; #value
	}
	if ($type eq "nexthop") {
	    $totalattrib_length += 2; #attr-flag! attr_type_code
	    $totalattrib_length += 1; #length
	    $totalattrib_length += 4; #ip address
	}
	elsif ($type eq "aspath") {
	    $totalattrib_length += 2; #attr-flag! attr_type_code
	    $totalattrib_length += 1; #length

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
	    foreach $set (@sets) {
		print "$nset $set \n";
	    }

	    # see how many bytes this all takes up
	    foreach $i (0..$nset) {
		@s = split (/\s+/, $sets[$i]);
		print "$i $#s @s\n";
		$totalattrib_length += 1; # segment type 
		$totalattrib_length += 1; # length
		$totalattrib_length += (2 * $#s);
	    }
	}
	elsif ($type eq "multiexit") {  
	    $totalattrib_length += 2; #attr-flag! attr_type_code
	    $totalattrib_length += 1; #length 
	    $totalattrib_length += 4; #value 
	}
	elsif ($type eq "atomic_aggregate") {
	    $totalattrib_length += 2; #attr-flag! attr_type_code
	    $totalattrib_length += 1; #length 
	    $totalattrib_length += 0; #value 
	}
	elsif ($type eq "aggregator") {
	    $totalattrib_length += 2; #attr-flag! attr_type_code
	    $totalattrib_length += 1; #length 
	    $totalattrib_length += 6; #value 
	}
    }


    # nlri calculations
    foreach $route (@routes) {
	($prefix, $length) = split (/\//, $route);
	$byte = &bytes ($length);
	$nlri_byte += (1 + $byte);
    }


    $length = 12 + 2 + 2 + $totalattrib_length + $nlri_byte;

    # MRT MSG header
    &print_mrt_header ($time, $length, $src, $dst);

    # total withdrawn routes field
    print OUT pack ('C2', 0);

    # total path attribute length
    print OUT pack ('S', $totalattrib_length);

    # path attributes 
    foreach $attr (@attr) {
	($type, @value) = split (/\s+/, $attr);
	if ($type eq "origin") {
	    #attr-flag | attr_type_code | length
 	    print OUT pack ("C1C1C1", 0x40, 1, 1); 
	    print OUT pack ("C1", $ORIGIN_HASH[$value[0]]);      # origin
	}
	elsif ($type eq "aspath") {
	    print OUT pack ("C1C1", 0x40, 2); #attr-flag! attr_type_code
	    $length = 0;
	    foreach $i (0..$nset) {
		@s = split (/\s+/, $sets[$i]);
		$length += 2 + 2* $#s;
	    }
	    #print OUT pack ("C1", 2 + 2*($#value + 1)); # length
	    print OUT pack ("C1", $length);

	    # okay, now encode each set/sequence
	    foreach $i (0..$nset) {
		@s = split (/\s+/, $sets[$i]);
		$t = shift (@s);
		if ($t eq "seq") {
		    print OUT pack ("C1", 2);      # sequence
		}
		else {
		    print OUT pack ("C1", 1);      # set
		}
		#print OUT pack ("C1", ($#value + 1));  num as's
		print OUT pack ("C1", ($#s + 1));  #num as's
		#foreach $as (@value) { 
		foreach $as (@s) {  
		    print OUT pack ("S", $as);
		}
	    }
	}
	elsif ($type eq "nexthop") {
	    @addr = split (/\./, $value[0]);
	    #attr-flag | attr_type_code | length
	    print OUT pack ("C1C1C1", 0x40, 3, 4);
	    print OUT pack ("C4", @addr);
	}
	elsif ($type eq "multiexit") {
	    @addr = split (/\./, $value[0]);
	    #attr-flag | attr_type_code | length
	    print OUT pack ("C1C1C1", 0x80, 4, 4);
	    print OUT pack ("N", $value[0]);
	}
	elsif ($type eq "atomic_aggregate") {
	    #attr-flag | attr_type_code | length
	    print OUT pack ("C1C1C1", 0x40, 6, 0);
	}
	elsif ($type eq "aggregator") { 
	    @addr = split (/\./, $value[1]);
	    #attr-flag | attr_type_code | length
	    print OUT pack ("C1C1C1", 0xc0, 7, 6);
	    print OUT pack ("SC4", $value[0], @addr);
	}
    }

    # add nlri
     foreach $route (@routes) {
	 ($prefix, $length) = split (/\//, $route);
	 @prefix = split (/\./, $prefix);
	 $byte = &bytes ($length);
	 print OUT pack ("C1C$byte", $length, @prefix);
     }
}


# someday I will learn how to do integer division in perl... (sigh)
sub bytes {
    local ($length) = @_;

    if ($length <= 8) { return (1);}
    if ($length <= 16) {return (2);}
    if ($length <= 24) {return (3);}
    
    return (4);
}


sub gettime {
    local ($month, $mday, $year, $hours, $min, $sec) = @_;
    $month--;
    #print "GETTIME $month/$mday/$year $hours:$min:$sec\n";
    $out = timelocal($sec,$min,$hours,$mday,$month, $year);
    #print "$hours $minc $sec $out\n";    
    return ($out);
}

