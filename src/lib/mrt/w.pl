#!/usr/local/bin/perl

while (1) {
    $n++;
    $v1 = $n * (log (2)) * .01;
    $v2= log (100) + 100*log ($n);
    #print $n, "  $v1 $v2\n";
    if ($v1 > $v2) {
	print "$n: $v1 $v2\n";
	exit;
    }
}

