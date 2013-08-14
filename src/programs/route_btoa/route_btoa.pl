#!/usr/local/bin/perl
#
# $Id: route_btoa.pl,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
#
# Name:    route_btoa.pl
# Author:  Craig Labovitz (Merit Network, Inc.) <labovit@merit.edu>
#  A perl version of route_btoa
#
# CHANGE: 10/10/97 <labovit@merit.edu> -- added IPv6 support
#         implements some varient of draft-ietf-idr-bgp4-multiprotocol-01.txt
#
require "getopts.pl";

%origin  = (2, 'Incomplete', 1, 'EGP', 0, 'IGP');

&Getopts("f:i:");
if(defined $opt_f) { $INPUT = $opt_f;}
if(defined $opt_i) { $INPUT = $opt_i;}
if ($INPUT eq "") {&error;}


$MSG_PROTOCOL_BGP4PLUS	= 9;
$MSG_PROTOCOL_BGP	= 5;

open (INPUT, "$INPUT") || die "Could not open $INPUT $!\n";


while ($buf = &get(12)) {
    ($time, $type, $subtype, $length) = unpack ("NnnN", $buf);
    #print "$type $subtype \n";

    if ((($type != $MSG_PROTOCOL_BGP) && ($type != $MSG_PROTOCOL_BGP4PLUS))
	|| ($subtype != 1)) {
	&get ($length);
	#print "$length skip\n";exit;
	next;
    }
    #print "$type $subtype\n";

    #print "time=$time type=$type subtype=$subtype len=$length\n";
    ($sec, $min, $hour, $mday, $mon, $year, @junk) = localtime ($time);
    $mon++;
    
    # search on time
    if (($hour < $t_hour) || 
	(($hour == $t_hour) && ($min < $t_min))) {
	&get ($length);
	next;
    }
    if ($hour < 10) {$hour = "0$hour";}
    if ($min < 10) {$min = "0$min";}
    if ($sec < 10) {$sec = "0$sec";}
    $title = "TIME: $mon/$mday/$year $hour:$min:$sec\n";
    decode_bgp ($length);
}


sub decode_bgp {
    local ($size, $data) = @_;
    $read = 0;
    

    if (($HOST ne "") && ($HOST ne $srcip)) {
	&get ($length - 6);
	return;
    }

    if ($type == $MSG_PROTOCOL_BGP4PLUS) {
	print "\nTYPE: BGP4+/UPDATE\n";
    }
    else {
	print "\nTYPE: BGP/UPDATE\n";
    }
    print $title;
    
    #BGP4+ (IPv6)
    if ($type == $MSG_PROTOCOL_BGP4PLUS) {
	$buf = &get (18);
	($srcas, @srcip) = unpack ("SC16", $buf);
	print "FROM: ", &ipv6_addr (@srcip);
	#$h = 0;
	#foreach $b (@srcip) {
	#if ($h++ == 2) {$h = 0; print ":";}
	#printf "%2.2x", $b;
	#}	
	print "  AS$srcas\n";
    }
    # standard BGP4
    else {
	$buf = &get (6);
	($srcas, @srcip) = unpack ("SC4", $buf);
	$srcip = join ('.', @srcip);
	if ($srcas !=0) {print "FROM: $srcip AS$srcas\n";}
    }

    # BGP4+ (IPv6)
    if ($type == $MSG_PROTOCOL_BGP4PLUS) {
	$buf = &get (18);
	($dstas, @dstip) = unpack ("SC16", $buf);
	if ($dstas !=0) {
	    print "TO: ", &ipv6_addr (@dstip);;
	    #$h = 0;
	    #foreach $b (@dstip) {
	    #if ($h++ == 3) {$h = 0; print ":";}
	    #	printf "%x", $b;
	    #}
	    print " AS$dstas\n";}
    }
    # BGP4
    else {
	$buf = &get (6);
	($dstas, @dstip) = unpack ("SC4", $buf);
	$dstip = join ('.', @dstip);
	if ($dstas !=0) {print "TO: $dstip AS$dstas\n";}
    }

    $buf = &get (2);
    $totalwithbyte = unpack ("S", $buf);
    #print "totalwith = $totalwithbyte\n";

    if ($totalwithbyte > 0) {
	print "WITHDRAW:\n";
    }

    while ($totalwithbyte > 0) {
	$buf = &get(1);
	$bitlen = unpack ("C1", $buf);
	$bytes = &bytes ($bitlen);
	$buf = &get ($bytes);
	@addr = unpack ("C$bytes", $buf);
	$addr = join ('.', @addr);
	print "  $addr/$bitlen\n";
	$totalwithbyte -= (1 + $bytes);
    }


    # total path attributes field
    $buf = &get (2);
    $total = unpack ('S', $buf);
    #print "total = $total\n"; 

    while ($total > 0) {
	#attr-flag | attr_type_code | length
	$buf = &get (2);
	($flag, $type) = unpack ("C2", $buf);

	# extended length
	if (vec ($flag, 0, 1)) {
	    $buf = &get (2);
	    $alen = unpack ("S", $buf);
	    $total -= 4;
	}
	# one byte length
	else {
	    $buf = &get (1);
	    $alen = unpack ("C", $buf);
	    $total -= 3;
	}

	#printf "Ox%x $type $alen\n", $flag;
	$total -= $alen;

	if ($type == 1) {
	    $buf = &get(1);
	    $org = unpack ("C", $buf);
	    print "ORIGIN: $origin{$org}\n";
	}
	elsif ($type == 2) {

	    print "ASPATH: ";
	    while ($alen > 0) {
		$buf = &get (2);
		($seg_type, $seg_len) = unpack ("CC", $buf);
		$alen -= 2;

		if ($seg_type == 1) {   print "[ "; }

		while ($seg_len-- > 0) {
		    $buf = &get (2);
		    $alen -= 2;
		    $as = unpack ("S", $buf);
		    print "$as ";
		}

		if ($seg_type == 1) {   print "] "; }
	    }
	    print "\n";
	}
	elsif ($type == 3) {
	    $buf = &get (4);
	    @addr = unpack ("C4", $buf);
	    $addr = join ('.', @addr);
	    print "NEXT_HOP: $addr\n";
	}
	elsif ($type == 4) {
	    $buf = &get (4); 
	    $val = unpack ("N", $buf);
	    print "MULTI_EXIT_DISC: $val\n";
	}
	elsif ($type == 6) {
	    print "ATOMIC_AGGREGATE\n";
	}
	elsif ($type == 7) {
	    $buf = &get (2); 
	    $as = unpack ("S", $buf);
	    $buf = &get (4); 
	    @addr = unpack ("C4", $buf);
	    $addr = join ('.', @addr);
	    print "AGGREGATOR: $as $addr\n";
	}
	elsif ($type == 14) {
	    $buf = &get (2);
	    $address_family = unpack ("S", $buf);

	    $sub_address_family = &get(1);
	    #print "ADDR FAMILY: $address_family ($sub_address_family)\n";

	    $buf = &get(1);
	    $length_next_hop = unpack ("C", $buf);

	    $buf = &get ($length_next_hop);
	    $l = $length_next_hop;
	    if ($length_next_hop > 16) {
		$l = 16;
	    }
	    @next_hop = unpack ("C$l", $buf);
	    print "NEXT_HOP: ", &ipv6_addr (@next_hop), "\n";
	    #$h = 0;
	    #foreach $b (@next_hop) {
	    #if ($h > 1) {$h = 0; print ":";}
	    #$h++;
	    #printf "%0+2x", $b;
	    #}
	    #print "\n";

	    # num smpa
	    $buf = &get (1);	    
	    $num_snpa = unpack ("C", $buf);

	    while ($num_snpa-- > 0) {
		print "here\n";
		$snpa_len = &get (1);
		$snpa = &get ($snpa_len);
	    }
	    
	    $buf = &get (2);
	    $nlen = unpack ("S", $buf);


	    #print "len $len\n"; 

	    print "ANNOUNCE:\n";

	    while ($nlen > 0) {
		$buf = &get (1);
		$nbit = unpack ("C", $buf);
		$len = $nbit / 8;  # have to round up here!!!!**********
		if ($nbit % 8 != 0) {$len++; $len = int $len;}
		#print "len $len\n";
		$buf = &get ($len);
		@nlri = unpack ("C$len", $buf);	    

		print "  ", &ipv6_addr (@nlri);
		#$h = 0;
		#print "  ";
		#foreach $b (@nlri) {
		#    if ($h > 1) {$h = 0; print ":";}
		#    $h++;
		#   printf "%0+2x", $b;
		#}
		print "/$nbit\n";
		$nlen =- $len;
	    }
	}
	# MP_UNREACH_NLRI
	elsif ($type == 15) {
	    $buf = &get (2);
	    $address_family = unpack ("S", $buf);
	    $buf = &get (1);
	    $sub_address_family = unpack ("C", $buf);
	    $alen -= 3;
	    
	    print "WITHDRAWN: \n";
	    # in a while loop decrementing alen
	    while ($alen > 0) {
		$buf = &get (1);
		$alen--;
		$nbit = unpack ("C", $buf);
		$len = $nbit / 8;
		if ($len != int $len) {
		    $len++; $len = int $len;
		}
		$buf = &get ($len);
		@prefix = unpack ("C$len", $buf);
		print "  ", &ipv_addr (@prefix), "\n";
		$alen -= $len;
	    }
	}
	else {
	    print "unknown attribute $type\n";
	    exit;
	}
    }

    #print "read $read size $size\n";

    if ($read < $size) {
	print "ANNOUNCE:\n";
    }
    while ($read < $size) {
	$buf = &get (1);
	$length = unpack ("C", $buf);
	#print "length = $length $read\n";exit;

	$bytes = &bytes ($length);
	$buf = &get ($bytes);
	@addr = unpack ("C$bytes", $buf);
	$addr = join ('.', @addr);
	print "  $addr/$length\n";
    }
}




sub print_mrt_header {
    local ($time, $length, $src, $dst) = @_;
    $type = 5;    #BGP
    $subtype = 1; #update

    @src = split (/\./, $src);
    @dst = split (/\./, $dst);
    if ($DEBUG) {
	print OUT pack ("NnnN", $time, $type, $subtype, $length);
	print OUT pack ('SC4', 0, @src);
	print OUT pack ('SC4', 0, @dst);
    }

    print TCP pack ("NnnN", $time, $type, $subtype, $length);
    print TCP pack ('SC4', 0, @src);
    print TCP pack ('SC4', 0, @dst);

}
    

# someday I will learn how to do integer division in perl... (sigh)
sub bytes {
    local ($length) = @_;

    if ($length <= 8) { return (1);}
    if ($length <= 16) {return (2);}
    if ($length <= 24) {return (3);}
    
    return (4);
}




sub get {
    local ($bytes) = @_;
    
    $buf = "";
    if (($n = read (INPUT, $buf, $bytes)) != $bytes) {
	if (($n == 0) && ($bytes == 12)) {exit;}
	print "read $n bytes, expected $bytes\n";
	exit;
    }
    
    $read += $bytes;
    return ($buf);
}


sub error {
    print "Usage: route_btoa.pl -i binary_data_file\n";
    exit;
}


sub ipv6_addr {
    local (@addr) = @_;


    $h = 0;
    $tmp = "";
    $addr = "";
    foreach $b (@addr) {
	#print "$b\n";
	$tmp = sprintf "%2.2x", $b;
	#printf "%2.2x", $b;
	$addr .= $tmp;
	if ($h++ == 1) {$h = 0; $addr .= ":";}
    }
    if ($addr =~ /\w\:$/) {
	if ($addr =~ /\:$/) { chop ($addr);}
    }

    
    @a = split ('\:', $addr);
    $aout= "";
    $skip = 0;
    foreach $a (@a) {
	if ($a eq "0000") {
	    if ($skip++ == 0) {
		$aout .= ":";
	    }
	    next;
	}
	if ($a =~ /^0+(\w+)$/) {
	    $a = $1;
	}
	# only one byte
	if ($a =~ /^(\d)$/) {$a ="$1" . "00";}
	$aout .="$a:";
    }
    chop ($aout);

    #print "$aout\n";
    #print "$addr\n"; exit;
    return ($aout);
}
