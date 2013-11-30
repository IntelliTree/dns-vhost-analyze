#! /usr/bin/perl

use strict;
use warnings;
use lib '/opt/sbl/scripts/include';
use Try::Tiny;
use Getopt::Long;
use Pod::Usage 'pod2usage';
use Socket 'inet_ntoa';
use Data::Dump 'dump';
use JSON;

=head1 NAME

vhost-dns-analyze.pl - analyze DNS vs whois, apache2 vhosts vs DNS, or both

=head1 SYNOPSIS

# standard usage
vhost-dns-analyze.pl --dns=SOURCE --vhost=SOURCE > combined_output.tsv

# or collect it from different computers (ie NS1 and Webserver)
vhost-dns-analyze.pl --dns=SOURCE --dump-dns=dns_entries.tsv
vhost-dns-analyze.pl --vhost=SOURCE --dump-vhost=vhost_entries.tsv


 Option Summary:
   --help              brief help
   --man               full documentation
   --dns mydns         check dns entries from "dbi:mysql:host=localhost;database=mydns:rr"
   --dns dbi:DSN:TABLE check dns entries from compatible table (dbi:mysql:param1;..paramN;:TABLE)
   --dns json:FILENAME check dns entries from previously dumped TSV file
   --expected-ns LIST  set list of expected nameservers for the DNS records
   --dump-dns FILE     writes DNS entries to FILE as json
   --vhost apache2     check virtual hosts from "/etc/apache2/httpd.conf"
   --vhost cfg:FILE    check virtual hosts from alternate apache configfile
   --vhost json:FILE   check virtual hosts from previously dumped vhost data
   --expected-ip LIST  set list of expected public IP addrs for the vhosts
   --dump-vhost FILE   print virtual hosts to FILE as json

=head1 CHANGELOG

=over

=item 0.01 - 2013-11-29, MLC

Initial version, scans soa table and apache configs and does name lookups on them
Dropped original "whois" strategy in favor of "dig +trace".

=cut

our $VERSION= '0.01';

my @dns_source;
my @vhost_source;
my ($dump_dns, $dump_vhost);
my (@expected_nameservers, @expected_webaddrs);
my $hide_duplicate_rows;
my %dns_cache;
my %ns_cache;

GetOptions (
	'help|?'              => sub { pod2usage(1); },
	'man'                 => sub { pod2usage(-exitval => 1, -verbose => 2); },
	'dns=s'               => sub { push @dns_source, $_[1] },
	'vhost=s'             => sub { push @vhost_source, $_[1] },
	'dump-dns=s'          => \$dump_dns,
	'dump-vhost=s'        => \$dump_vhost,
	'expected-ns=s'       => sub { push @expected_nameservers, split(',', $_[1]) },
	'expected-ip=s'       => sub { push @expected_webaddrs, split(',', $_[1]) },
) or pod2usage();

@dns_source or @vhost_source
	or die "Require at least one --dns or --vhost option\n";
@expected_nameservers= ('ns1.intellitree.com', 'ns2.intellitree.com')
	unless @expected_nameservers;
@expected_webaddrs= map { ($_ =~ /^(10\.|172\.(16|17|18|19|2\d|30|31)\.|192\.168\.|127\.|169\.254\.)/)? () : ($_) } (`ifconfig -a` =~ /inet addr:(\S+)/g)
	unless @expected_webaddrs;

exit run();

sub run {
	my @dns_data;
	my @vhost_data;
	
	# Collect list of all dns to check from specified sources
	for my $dns_src (@dns_source) {
		if ($dns_src eq 'mydns') {
			my $home= $ENV{HOME} || '/root';
			dns_merge(\@dns_data, dns_load_dbi("dbi:mysql:mysql_read_default_file=$home/.my.cnf;host=localhost;database=mydns", 'soa'));
		} elsif ($dns_src =~ /^(dbi.*):([^:]+)$/) {
			dns_merge(\@dns_data, dns_load_dbi($1, $2));
		} elsif ($dns_src =~ /^json:(.*)$/) {
			dns_merge(\@dns_data, dns_import($1));
		} else {
			die "Unrecognized spec for dns data: \"$dns_src\"\n";
		}
	}

	# Collect all vhost to check from specified sources
	for my $vhost_src (@vhost_source) {
		if ($vhost_src eq 'apache2') {
			vhost_merge(\@vhost_data, vhost_load_apachecfg('/etc/apache2/httpd.conf'));
		} elsif ($vhost_src =~ /^cfg:(.*)$/) {
			vhost_merge(\@vhost_data, vhost_load_apachecfg($1));
		} elsif ($vhost_src =~ /^json:(.*)$/) {
			vhost_merge(\@vhost_data, vhost_import($1));
		} else {
			die "Unrecognized spec for vhost data: \"$vhost_src\"\n";
		}
	}
	
	# Save copies of vhost and dns items if user requested it
	vhost_export(\@vhost_data, $dump_vhost)
		if defined $dump_vhost;
	dns_export(\@dns_data, $dump_dns)
		if defined $dump_dns;
	
	# Analyze the items
	my $result= analyze(\@dns_data, \@vhost_data);
	
	# Display results as tsv
	print_analysis($result);
	
	# Success if and only if all lookups matched expectations
	return 1 if $result->{err};
	return 0;
}

# Merge two arrays of dns-check data.  This is only necessary because I
# wanted to store them as arrays.  (they were originally tables)
sub dns_merge {
	my ($table1, $table2)= @_;
	# Die on conflicting rows, treating domain as primary key.
	my $i= 0;
	my %by_domain= map { $_->{domain} => $i++ } @$table1;
	for my $rec (@$table2) {
		my $domain= $rec->{domain};
#		$domain =~ /(^|\.)([^.]+\.[^.]+)\.$/
#			or die "Invalid dns name: \"$domain\"";
#		$domain= $2;
		if (exists $by_domain{$domain}) {
			die "nameserver mismatch: $domain maps to both $table1->[$by_domain{$domain}]{nameserver} and $rec->{nameserver}\n"
				unless $table1->[$by_domain{$domain}]{nameserver} eq $rec->{nameserver};
		} else {
			push @$table1, $rec;
			$by_domain{$domain}= $i++;
		}
	}
	$table1;
}

# Load dns names from specified DB/table/column
sub dns_load_dbi {
	my ($dsn, $table, $column)= @_;
	require DBI;
	my $db= DBI->connect($dsn, undef, undef, { RaiseError => 1, AutoCommit => 1 })
		or die "DBI should have thrown an error";
	my $rows= $db->selectall_arrayref(
		'SELECT '.$db->quote_identifier($column)
		.' FROM '.$db->quote_identifier($table),
		{ Slice => [0] }
	);
	# For each row, build a record of domain-name and expected nameservers
	for (@$rows) {
		my $d= lc($_->[0]);
		$d =~ s/\.$//;
		$_= { domain => $d, nameserver => \@expected_nameservers };
	}
	$rows;
}

sub dns_import {
	my ($file)= @_;
	open(my $fd, "<", $file) or die "open($file): $!";
	local $/= undef;
	my $table= decode_json(<$fd>);
	$table;
}

sub dns_export {
	my ($table, $file)= @_;
	open(my $fd, ">", $file) or die "open($file): $!";
	print $fd encode_json($table)."\n";
	close $fd or die "close($file): $!";
}

# Merge two arrays of vhost-check data.  This is only necessary because I
# wanted to store them as arrays.  (they were originally tables)
sub vhost_merge {
	my ($table1, $table2)= @_;
	# die on conflicting rows, treating hostname as primary key.
	my $i= 0;
	my %by_name= map { $_->[0] => $i++ } @$table1;
	for my $rec (@$table2) {
		my $hostname= $rec->{hostname};
		if (exists $by_name{$hostname}) {
			die "server mismatch: $hostname maps to both $table1->[$by_name{$hostname}][1] and $rec->{server}\n"
				unless $table1->[$by_name{$hostname}]{server} eq $rec->{server};
#			die "site_id mismatch: $hostname maps to both $table1->[$by_name{$hostname}]{site_id} and $rec->{site_id}\n"
#				unless $table1->[$by_name{$hostname}]{site_id} eq $rec->{site_id};
		} else {
			push @$table1, $rec;
			$by_name{$hostname}= $i++;
		}
	}
	$table1;
}

# Rudimentary parsing of apache config.  Not intended to be perfect
sub vhost_load_apachecfg {
	my ($fname)= @_;
	my @worklist= ($fname);
	my %seen= ($fname => 1);
	my %hostnames;
	while (@worklist) {
		my $f= pop @worklist;
		my $cfg_txt= do { open(my $fh, "<", $f) or die "Can't open $f: $!"; local $/= undef; <$fh> };
		for ($cfg_txt =~ /^\s*Server(?:Name|Alias)\s+(\S+)/mg) {
			next unless $_ =~ /\.\D/;
			$hostnames{$_}= { hostname => lc($_), server => \@expected_webaddrs, cfg_file => $f };
		}
		push @worklist, grep { !$seen{$_}++ }
			map { index($_, '*') >= 0 ? eval "<$_>" : ($_) }
				($cfg_txt =~ /^\s*Include\s+(\S+)/mg);
	}
	[ values %hostnames ];
}

sub vhost_import {
	my ($file)= @_;
	open(my $fd, "<", $file) or die "open($file): $!";
	local $/= undef;
	my $table= decode_json(<$fd>);
	$table;
}

sub vhost_export {
	my ($table, $file)= @_;
	open(my $fd, ">", $file) or die "open($file): $!";
	print $fd encode_json($table)."\n";
	close $fd or die "close($file): $!";
}

# Simple dns resolve, using gethostbyname
# Fails with string "(unresolvable)"
sub dns_resolve {
	my ($host)= @_;
	$host= lc($host);
	return $dns_cache{$host}
		if exists $dns_cache{$host};
	my $ip= gethostbyname($host)
		or do { warn "gethostbyname($host): $!"; return '(unresolvable)'; };
	$ip= $dns_cache{$host}= inet_ntoa($ip);
	print STDERR "Resolved $host as $ip\n";
	return $ip;
}

# Resolve nameservers for $domain.  Be smart, and travel the nameserver
# hierarchy, instead of trusting the NS records of the leaf server.
sub ns_resolve {
	my ($domain)= @_;
	$domain= lc($domain);
	return [ @{$ns_cache{$domain}} ]
		if exists $ns_cache{$domain};
	my @ns;
	my @out;
	my $tries= 5;
	my $wstat;
	while ($tries--) {
		# dig +trace to query nameservers in sequence from root to leaf.
		@out= `dig +trace +authority +additional -t NS $domain`;
		# dig might fail because it can't reach the final nameserver,
		# but we don't care.  Try parsing it anyway and continue if we
		# get our NS records from the parent server.
		$wstat= $?;
		my $done= 0;
		for (@out) {
			# The NS records we want are the very first ones which refer to $domain,
			# which should be reported by the parent of the leaf nameserver.
			push @ns, $1
				if !$done and index($_, $domain) == 0 and ($_ =~ /NS\s+(\S+)\.\s*$/);
			# Once we collect NS records from the parent, ignore everything from the leaf itself.
			$done= 1
				if @ns && ($_ =~ /^;;/);
			# While we're at it, stuff any A records we find into the dns_cache.
			$dns_cache{$1}= $2
				if $_ =~ /^(\w+\S+)\.\s+\S+\s+\S+\s+A\s+(\d\S+)\s*$/;
		}
		# If we got our NS records, or if dig exited cleanly, return results.
		last if @ns || ($wstat == 0);
		# Else wait and try again in case temporary failure
		print STDERR "trouble looking up $domain\n@out\n";
		sleep 2;
	}
	print STDERR "Resolved NS for $domain as (@ns)\n";
	\@ns;
}

# Compares 2 lists for whether they have an element in common.
# Would be more efficient here if we had kept them as hashes all along.
sub _has_element_in_common {
	my ($list1, $list2)= @_;
	my %x= map { $_ => 1 } @$list1;
	$x{$_} and return 1
		for @$list2;
	return 0;
}

# Perform real-world lookups on the DNS and vhost data
sub analyze {
	my ($dns_data, $vhost_data)= @_;
	my %result= (
		domains => {},
		hosts => {},
		err_wrong_nameserver => 0,
		err_wrong_webserver  => 0,
		err => 0
	);
	for my $rec (@$dns_data) {
		my $d= $rec->{domain};
		my $whois= ns_resolve($d);
		my $whois_ip= [ map { dns_resolve($_) } @$whois ];
		my $expected= $rec->{nameserver} || [];
		my $expected_ip= [ map { dns_resolve($_) } @$expected ];
		# strip trailing dot
		$d =~ s/\.$//;
		#print STDERR "$d ( @$whois_ip ) expect $ip\n";
		$result{domains}{$d}= {
			dns_expected    => $expected,
			dns_expected_ip => $expected_ip,
			dns_actual      => $whois,
			dns_actual_ip   => $whois_ip,
			dns_correct     => _has_element_in_common( $expected_ip, $whois_ip ),
		};
		$result{err_wrong_nameserver}= 1
			unless $result{domains}{$d}{dns_correct};
	}
	for my $rec (@$vhost_data) {
		my $host= lc($rec->{hostname});
		$host =~ /((?:[^.]+.)?[^.]+)$/
			or die "Can't determine domain of hostname \"$host\"\n";
		my $d= $1;
		my $expected= $rec->{server} || [];
		my $expected_ip= [ map { dns_resolve($_) } @$expected ];
		my $actual_ip= dns_resolve($host);
		$result{hosts}{$host}= {
			%$rec,
			domain         => $1,
			hostname       => $host,
			expected       => $expected,
			expected_ip    => $expected_ip,
			actual         => $host||'',
			actual_ip      => $actual_ip||'',
			ip_correct     => _has_element_in_common( [ $actual_ip ], $expected_ip ),
		};
		$result{err_wrong_webserver}= 1
			unless $result{hosts}{$host}{ip_correct};
	}
	$result{err}= $result{err_wrong_nameserver} || $result{err_wrong_webserver};
	return \%result;
}

# Print the analysis as a side-by-side table of Nameserver lookup
# and Vhost name lookup similar to an outer join, to make it easy
# compare both kinds of records at once.
sub print_analysis {
	my ($analysis)= @_;
	my $domains= $analysis->{domains};
	my $hosts= $analysis->{hosts};
	# print sorted by domain
	print "DOMAIN\tDNS_CORRECT\tFOREIGN_DNS\tHOSTNAME\tHOST_CORRECT\tFOREIGN_HOST\n";
	my %all_by_domain= %$domains;
	for (values %$hosts) {
		$all_by_domain{$_->{domain}}{hosts}{$_->{hostname}}= $_;
	}
	for my $d (sort keys %all_by_domain) {
		my ($domain, $dns_correct, $foreign_dns)= ($d, '-', '-');
		if ($domains->{$d}) {
			$dns_correct= $domains->{$d}{dns_correct}? 'Y' : 'N';
			$foreign_dns= $domains->{$d}{dns_correct}? '-'
				: @{$domains->{$d}{dns_actual}}? $domains->{$d}{dns_actual}[0]
				: '(?)';
		}
		if ($all_by_domain{$d}{hosts}) {
			for (sort keys %{$all_by_domain{$d}{hosts}}) {
				my $h= $all_by_domain{$d}{hosts}{$_};
				print join("\t", $domain, $dns_correct, $foreign_dns, $h->{hostname}, $h->{ip_correct}? ('Y', '') : ('N', $h->{actual_ip}))."\n";
			}
			$domain= $dns_correct= $foreign_dns= ''
				if $hide_duplicate_rows;
		} else {
			print join("\t", $domain, $dns_correct, $foreign_dns, '', '', '')."\n";
		}
	}
	
	return { error_detected => 0 };
}
