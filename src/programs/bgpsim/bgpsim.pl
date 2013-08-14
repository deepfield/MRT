#!/bin/perl
#
# $Id: bgpsim.pl,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
#
#
# Program: BGPSIM.pl
#
# Unlink the C code version, this perl code does not keep state. Just 
# generates lots and lots of somewhat random BGP traffic
# A hack, but somewhat useful....

#####################################################################
#
# OPTIONS
#

# Interval (in seconds) between BGP packets
$INTERVAL_MAX = 5;

# BGP peers
@PEERS = ("AS2884 192.157.69.250/32", "AS540 192.157.69.251/32");


####################################################################



# Set a somewhat random seed
srand (time|$$);


while (1) {


($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) =
    localtime (time);

print "TIME: $mon/$mday/$year $hour:$min:$sec\n";
print "TYPE: BGP/UPDATE\n";
&sim_peer ();

print "ASPATH: ";
&sim_aspath;

print "ORIGIN: IGP\n";
print "NEXT_HOP: 192.157.69.250/32\n";
print "MULTIEXIT: 4\n";
print "ANNOUNCE:\n";
&sim_announce;
print "\n";


&sim_sleep ();


}


sub sim_peer {
    $e = $#PEERS;
    $number = int(rand($#PEERS + 1));

    #print "print "Peers = $number $e\n";
    print "FROM: $PEERS[$number]\n";
		       
}

sub sim_announce {
    $number = int(rand(12)) + 1;
    
    for ($i=0; $i< $number; $i++) {
	$length = 1+ int(rand(10));
	
	# a /8
	if ($length == 1) {
	    $prefix = 10 + int(rand(119));
	    print "  $prefix/8\n";
	}
	elsif (($length == 2) || ($length == 3)) {
	    $prefix1 = 128 + int(rand(64));
	    $prefix2 = int(rand(254));
	    print "  $prefix1.$prefix2/16\n";
	}
	else {
	    $prefix1 = 192 + int(rand(32));
	    $prefix2 = int(rand(254));
	    $prefix3 = int(rand(254));
	    print "  $prefix1.$prefix2.$prefix3/24\n";
	}
    }
}

sub sim_aspath {
    
    $length = 1+ int(rand(12));
    for ($i=0; $i< $length; $i++) {
	$as = int(rand(6500));
	print "$as ";
    }

    print "\n";

}

sub sim_sleep {

$wait = int(rand($INTERVAL_MAX));
#print "Sleeping for $wait\n";
sleep ($wait);


}
