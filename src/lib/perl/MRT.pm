package MRT;


use English;
use Carp;

# use strict;
use integer;


sub main'get_mrt_header {
    my $time;
    my $type;
    my $subtype;
    my $length;
    my $buf = &get(12);

    ($time, $type, $subtype, $length) = unpack ("NnnN", $buf);
    if ($buf eq "") {$time = -1;}

    return ($time, $type, $subtype, $length, $buf);
}



sub main'open_mrt_data {
    local ($name) = @_;

    if ($name eq "") {
      die "Null argument to open_mrt_data\n";
    }

    open (INPUT, $name) || die "\nCould not open $name\n";
}

sub main'close_mrt_data {
  close (INPUT);

  return (1);
}

# someday I will learn how to do integer division in perl... (sigh)
sub bytes {
    local ($length) = @_;

    if ($length <= 8) { return (1);}
    if ($length <= 16) {return (2);}
    if ($length <= 24) {return (3);}
    
    return (4);
}



sub main'get_mrt_bgp_msg {
    my $srcip; my $srcas;
    my $dstip; my $dstas;
    my $ann_prefix = "";
    my $with_prefix = "";
    my $aspath = "";
    my $origin;
    my $nexthop;

    local ($size) = @_;
    $read = 0;

    $buf = &get (6);
    ($srcas, @srcip) = unpack ("SC4", $buf);
    $srcip = join ('.', @srcip);

    $buf = &get (6);
    ($dstas, @dstip) = unpack ("SC4", $buf);
    $dstip = join ('.', @dstip);

    $buf = &get (2);
    $totalwithbyte = unpack ("S", $buf);
    #print "totalwith = $totalwithbyte\n";

    while ($totalwithbyte > 0) {
	$buf = &get(1);
	$bitlen = unpack ("C1", $buf);
	$bytes = &bytes ($bitlen);
	$buf = &get ($bytes);
	@addr = unpack ("C$bytes", $buf);
	$addr = join ('.', @addr);
	#print "  $addr/$bitlen\n";
	$with_prefix .= "$addr/$length ";
	$totalwithbyte -= (1 + $bytes);
    }


    # total path attributes field
    $buf = &get (2);
    $total = unpack ('S', $buf);
    #print "total = $total\n"; 

    while ($total > 0) {
	#attr-flag | attr_type_code | length
	$buf = &get (3);
	($flag, $type, $alen) = unpack ("C3", $buf);
	$total -= 3;
	$total -= $alen;

	if ($type == 1) {
	    $buf = &get(1);
	    $origin = unpack ("C", $buf);
	}
	elsif ($type == 2) {
	    while ($alen > 0) {
		$buf = &get (2);
		($seg_type, $seg_len) = unpack ("CC", $buf);
		$alen -= 2;

		while ($seg_len-- > 0) {
		    $buf = &get (2);
		    $alen -= 2;
		    $as = unpack ("S", $buf);
		    $aspath .= "$as ";
		}
	    }
	}
	elsif ($type == 3) {
	    $buf = &get (4);
	    @addr = unpack ("C4", $buf);
	    $nexthop = join ('.', @addr);
	}
	else {
	    print "unknown attribute $type\n";
	    exit;
	}
    }

    #print "read $read size $size\n";

    while ($read < $size) {
	$buf = &get (1);
	$length = unpack ("C", $buf);

	$bytes = &bytes ($length);
	$buf = &get ($bytes);
	@addr = unpack ("C$bytes", $buf);
	$addr = join ('.', @addr);
	$ann_prefix .= "$addr/$length ";
    }

    chop ($aspath); 
    return ($srcip, $srcas, $dstip, $dstas, $ann_prefix,
	    $with_prefix, $aspath, $origin, $nexthop, @attr);
}


sub get {
    local ($bytes) = @_;
    my $buf = "";

    if (($n = read (INPUT, $buf, $bytes)) != $bytes) {
	if (($n == 0) && ($bytes == 12)) {return "";}
	print "read $n bytes, expected $bytes\n";
	exit;
    }
    
    $read += $bytes;
    return ($buf);
}

sub main'mrt_skip {
  local ($len) = @_;

  &get ($len);
  return;
}

sub main'get_mrt_bgp_dead_msg {
  my $ip; my $as;
  $buf = &get(6);
  ($as, @ip) = unpack ("SC4", $buf);

  $ip = join (".", @ip);

  return ($as, $ip);
}


#
# given an IP address, return name of RS peer
#
sub main'get_peername {
    local ($ip) = @_;

    $name = $NAME{$ip};

    if ($name eq "") {$name = $ip;}

    return ($name);
}

%NAME=(#mae-east
       '192.41.177.110', 'Advantis (2685)',
       '192.41.177.145', 'AGIS (4200)',
       '192.41.177.249', 'Alternet (701)',
       '192.41.177.140', 'ANS (690)',
       '192.41.177.85', 'CAIS (3491)',
       '192.41.177.135', 'CWInet (4445)',
       '192.41.177.95', 'Delphi (5088)',
       '192.41.177.115', 'DIGEX (2548)',
       '192.41.177.226', 'DRAnet (1746)',
       '192.41.177.92', 'DXnet (3914)',
       '192.41.177.251', 'ESnet (293)',
       '192.41.177.252', 'ESnet (293)',
       '192.41.177.86', 'HLCnet (4565)',
       '192.41.177.75', 'IconNet (3951)',
       '192.41.177.155', 'INAP.net (5646)',
       '192.41.177.112', 'INSnet (5378)',
       '192.41.177.160', 'Interpath (3407)',
       '192.41.177.120', 'EUNet',
       '192.41.177.89', 'SuperNet (5422)',
       '192.41.177.80', 'IOSnet (5000)',
       '192.41.177.181', 'MCI (3561)',
       '192.41.177.132', 'Nacamar (3257)',
       '192.41.177.170', 'Net99 (3830)',
       '192.41.177.87', 'NetAxs (4969)',
       '192.41.177.210', 'Netcom (2551)',
       '192.41.177.228', 'Netrail (4006)',
       '192.41.177.190', 'PIPEX (1849)',
       '35.1.1.48', 'RSHIST (185)',
       '192.41.177.241', 'SPRINT (1239)',
       '192.41.177.6', 'Suranet (86)',
       '192.41.177.90', 'ThePlanet (5388)',
       '192.41.177.163', 'vBNS (145)',
       '192.41.177.150', 'WIS.COM (4136)',
	'192.157.69.20', 'Advantis (2685)',
 	# sprint
 	'192.157.69.19', 'AGIS (4200)',
       '192.157.69.60', 'AlterNet (701)',
       '192.157.69.4', 'ANS (690)',
       '192.157.69.5', 'CERFnet (1740)',
       '192.157.69.55', 'DREN (668)',
       '192.157.69.12', 'ESNET (293)',
       '192.157.69.70', 'IOSnet (5000)',
       '35.1.1.48', 'RSHIST (185)',
       '192.157.69.14', 'vBNS (145)',
       '192.157.69.10', 'WIS.COM (4136)',
       # aads
       '198.32.130.20', 'Alpha (4550)',
       '198.32.130.21', 'Argonne (683)',
       '198.32.130.39', 'NAP.NET (5646)',
       '198.32.130.15', 'NETCOM (2551)',
       '35.1.1.48', 'RSHIST (185)',
       '198.32.130.14', 'vBNS (145)',
       '198.32.136.20', 'Advantis (2685)',
       '198.32.136.32', 'AIMnet (3763)',
       '198.32.136.42', 'AlterNet (701)',
       '198.32.136.36', 'Best (3915)',
       '198.32.136.27', 'ConXioN (4544)',
       '198.32.136.41', 'ESnet (293)',
       '198.32.136.25', 'IconNet (3951)',
       '198.32.136.13', 'INAP.net (5646)',
       '198.32.136.38', 'InterNex (2828)',
       '198.32.136.40', 'ISI.Net (6196)',
       '198.32.136.50', 'MFSnet (6066)',
       '198.32.136.15', 'Netcom (2551)',
       '198.32.136.18', 'SCRUZnet (4436)',
       '198.32.136.29', 'Supernet (5422)',
       '198.32.136.35', 'ThePlanet (5388)',
	# pb
	'198.32.128.19', 'AGIS (4200)',
	'198.32.128.29', 'AimNet (3763)',
	'198.32.128.66', 'ANSnet (690)',
	'198.32.128.25', 'EXODUS (3967)',
	'198.32.128.24', 'GEOnet (3356)',
	'198.32.128.22', 'MIBX (6218)',
	'198.32.128.16', 'Net99 (3830)',
	'198.32.128.15', 'Netcom (2551)',
	'35.1.1.48', 'RSHIST (185)',
	'198.32.128.163', 'vBNS (145)',
	'198.32.128.26', 'WELL (4540)'
       );	

sub main'mrt_get {
    local ($bytes) = @_;
    my $buf = "";	

    if (($n = read (INPUT, $buf, $bytes)) != $bytes) {
        if (($n == 0) && ($bytes == 12)) {return "";}
        print "read $n bytes, expected $bytes\n";
        exit;
    }

    $read += $bytes;
    return ($buf);
}

return 1;


