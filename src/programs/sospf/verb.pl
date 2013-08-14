#!/usr/local/bin/perl

use integer;

$last = 0;
%rout_num;

$router_name{'198.108.90.5'} = 'MICHNET1';
$int_name{'198.108.0.1'} = 'Merit IE servers';
$int_name{'192.203.195.4'} = 'Interexchange network between MICHNET1 and MICHNET5';
$int_name{'198.108.22.101'} = 'T3 link to MSU2';

$router_name{'198.108.89.45'} = 'EMU';
$router_name{'198.108.91.5'} = 'MICHNET5';
$router_name{'198.108.131.5'} = 'WMU';
$router_name{'198.108.195.5'} = 'TCITY';
$router_name{'198.108.247.5'} = 'IRONMT';
$router_name{'198.109.37.5'} = 'WSU1';
$router_name{'198.109.39.5'} = 'UMD';
$router_name{'198.109.133.5'} = 'MSU';
$router_name{'198.109.133.169'} = 'VOYAGER2';
$router_name{'198.109.193.5'} = 'JACKSON';
$router_name{'198.109.134.33'} = 'STATEMICH';
$router_name{'198.109.225.5'} = 'BSPOP';
$router_name{'198.110.9.5'} = 'FLINT';
$router_name{'198.110.18.5'} = 'FLPOP';
$router_name{'198.110.39.5'} = 'MUSKPOP';
$router_name{'198.110.131.5'} = 'MTU';
$router_name{'198.110.69.5'} = 'GRPOP';
$router_name{'198.110.145.41'} = 'LTUPOP';
$router_name{'198.110.145.49'} = 'TACOM';
$router_name{'198.110.209.5'} = 'NMU';
$router_name{'198.110.209.25'} = 'LSSU';
$router_name{'198.111.3.5'} = 'OAKLAND';
$router_name{'198.111.129.5'} = 'CMU';
$router_name{'198.111.195.5'} = 'SAGPOP';
$router_name{'198.111.195.113'} = 'SAGINAW';


while (<>) {
    chop;
    @line = split /\|/;
    ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
	localtime($line[0]);    

    #if ($line[4] eq "(0)") {next;}


    if ($line[1] eq "RLSA") {
	printf("%02d:%02d:%02d - ", $hour, $min, $sec);

	print "Router $line[6] ($router_name{$line[6]}), age $line[2] ";

	if ($rout_num{$line[6]} eq "") {
	    $rout_num{$line[6]} = $last;
	    $name[$last] = $line[6];
	    $last++;
	}

	$my_num = $rout_num{$line[6]};

	$rout_int = $RLSA[$my_num]{'Interfaces'};
	if ($rout_int eq "") {
	    $rout_int = 0;
	}

	print "used to have $rout_int interfaces\n";

	# Assume all the interfaces are going down.
	foreach $key (keys %{$old_interfaces[$my_num]}) {
	    $new_interfaces[$my_num]{$key} = "DOWN";
	}

	$num_int = 0;
	for ($i = 7; $i < $#line; $i += 4) {
	    $num_int++;

	    if ($old_interfaces[$my_num]{$line[$i] . "-" .
					     $line[$i + 1] . "-" .
						 $line[$i + 3]}
		ne $line[$i + 2]) {

		printf(" %2d", $num_int);

		SWITCH : {
		    $_ = $line[$i];
		    if (/^1$/) {
			print "  Point-to-point:  ";
			print "$line[$i + 1] ($router_name{$line[$i + 1]})";
			print " - $line[$i + 3]   $line[$i + 2]";
			last SWITCH
			}
		    if (/^2$/) {
			print "  Transit network: ";
			print "$line[$i + 1] - $line[$i + 3]   $line[$i + 2]";
			last SWITCH
			}
		    if (/^3$/) {
			print "  Stub network:    ";
			print "$line[$i + 1] - $line[$i + 3]   $line[$i + 2]";
			last SWITCH
			}
		    if (/^4$/) {
			print "  Virtual link:    ";
			print "$line[$i + 1] - $line[$i + 3]   $line[$i + 2]";
			last SWITCH
			}
		}


		$old_metric = $RLSA[$my_num]{$line[$i + 1] . "-" . $line[$i +
									 3]};

		if ($old_metric ne "") {
		    print " <- $old_metric";
		}

		print "\n";
	    }

	    # Set the metric to the new metric.
	    $RLSA[$my_num]{$line[$i + 1] . "-" . $line[$i + 3]} = $line[$i + 2];

	    # Set the status of this interface to UP.
	    $new_interfaces[$my_num]{$line[$i] . "-" .
					 $line[$i + 1] . "-" .
					     $line[$i + 3]} =
						 $line[$i + 2];

	    
	}

	# Look for interfaces that went down.
	foreach $key (keys %{$new_interfaces[$my_num]}) {
	    if ($new_interfaces[$my_num]{$key} eq "DOWN" &&
		$old_interfaces[$my_num]{$key} ne "DOWN") {

		$key =~ /(.*)-(.*)-(.*)/;
		SWITCH : {
		    $link_id = $2;
		    $link_data = $3;
		    $_ = $1;
		    if (/^1$/) {
			print "  Point-to-point:  ";
			print "$link_id ($router_name{$link_id})";
			print " - $link_data";
			last SWITCH
			}
		    if (/^2$/) {
			print "  Transit network: ";
			print "$link_id - $link_data";
			last SWITCH
			}
		    if (/^3$/) {
			print "  Stub network:    ";
			print "$link_id - $link_data";
			last SWITCH
			}
		    if (/^4$/) {
			print "  Virtual link:    ";
			print "$link_id - $link_data";
			last SWITCH
			}
		}


		print " went down.\n";
	    }
	}

	# Set the number of interfaces.
	$RLSA[$my_num]{'Interfaces'} = $num_int;

	# Copy the new interface status to the old interface status.
	foreach $key (keys %{$new_interfaces[$my_num]}) {
	    $old_interfaces[$my_num]{$key} = $new_interfaces[$my_num]{$key};
	}

	print "\n";
	    
    } elsif ($line[1] eq "ELSAs") {
	$old_metric = $ELSA{$line[5] . $line[6] . $line[7]};

	if ($old_metric ne $line[8]) {
	    printf("%02d:%02d:%02d - ", $hour, $min, $sec);

	    print "External $line[5] ($router_name{$line[5]}), age $line[2]\n";

	    print "  $line[6] $line[7] : $line[8]";


	    if ($old_metric ne "") {
		print " <- $old_metric";
	    }

	    print "\n\n";
	}

	$ELSA{$line[5] . $line[6] . $line[7]} = $line[8];

    } elsif ($line[1] eq "NLSA") {
	printf("%02d:%02d:%02d - ", $hour, $min, $sec);

	print "Network $line[5] ($router_name{$line[5]}), age $line[2] ";

	if ($rout_num{$line[5]} eq "") {
	    $rout_num{$line[5]} = $last;
	    $name[$last] = $line[5];
	    $last++;
	}

	$my_num = $rout_num{$line[5]};

	$num_routers = $NLSA[$my_num];
	if ($num_routers eq "") {
	    $num_routers = 0;
	}

	print "used to have $num_routers routers\n";



	print "  Id: $line[6]  Mask: $line[7]\n";

	$num_routers = 0;
	for ($i = 8; $i <= $#line; $i++) {
	    $num_routers++;

	    printf("%3d", $num_routers);

	    print " $line[$i]\n";
	}

	print "\n\n";
    }
}
