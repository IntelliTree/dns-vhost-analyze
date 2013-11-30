#! /usr/bin/perl

use strict;
use warnings;
use lib '/opt/sbl/scripts/include';
use Try::Tiny;
use Log::Any '$log';
use Log::Any::Adapter;
use Getopt::Long;
use Pod::Usage 'pod2usage';
use Socket 'inet_ntoa';
use Data::Dump 'dump';

=head1 NAME

vhost-dns-analyze.pl - analyze DNS vs whois, apache2 vhosts vs DNS, or both

=head1 SYNOPSIS

vhost-dns-analyze.pl --dns=SOURCE > output_table.tsv
vhost-dns-analyze.pl --dns=SOURCE --dump-dns > dns_entries.tsv
vhost-dns-analyze.pl --vhost=SOURCE > output_table.tsv
vhost-dns-analyze.pl --vhost=SOURCE --dump-vhost > vhost_entries.tsv
vhost-dns-analyze.pl --dns=SOURCE --vhost=SOURCE > combined_output.tsv

 Option Summary:
   --help              brief help
   --man               full documentation
   --dns mydns         check dns entries from "dbi:mysql:host=localhost;database=mydns:rr"
   --dns dbi:DSN:TABLE check dns entries from compatible table (dbi:mysql:param1;..paramN;:TABLE)
   --dns data:FILENAME check dns entries from previously dumped TSV file
   --dump-dns          print DNS entries instead of analyzing anything
   --vhost apache2     check virtual hosts from "/etc/apache2/httpd.conf"
   --vhost cfg:FILE    check virtual hosts from alternate paache configfile
   --vhost data:FILE   check virtual hosts from previously dumped vhost data
   --dump-vhosts       print virtual hosts data instead of analyzing anything
   --whois-src HOST    use HOST for all live whois requests
   --dns-src HOST      use HOST for all live DNS queries
   --whois-cache FILE  use FILE for caching whois requests. created if needed.

=head1 CHANGELOG

=over

=item 0.01 - 2013-11-29, MLC

Initial version, scans zone table and runs whois on each entry

=cut

our $VERSION= '0.01';

my @dns_source;
my @vhost_source;
my ($dump_dns, $dump_vhost);
my ($whois_server, $dns_server, $whois_cache_file);
my ($cur_nameserver, $cur_webaddr)= ('ns1.intellitree.com', 'neutrino.intree.net');
my $hide_duplicate_rows;
my $apache_opts= '-D DEFAULT_VHOST -D PHP5 -D SVN -D DAV -D DAV_FS -D AUTH_PAM -D SSL -D SSL_DEFAULT_VHOST -D PROXY -D PROXY_HTML -D FASTCGI -D NO_DETACH';
my %whois_cache;
my %dns_cache;

GetOptions (
	'help|?'              => sub { pod2usage(1); },
	'man'                 => sub { pod2usage(-exitval => 1, -verbose => 2); },
	'dns=s'               => sub { push @dns_source, $_[1] },
	'vhost=s'             => sub { push @vhost_source, $_[1] },
	'dump-dns'            => \$dump_dns,
	'dump-vhost'          => \$dump_vhost,
	'apache-opts=s'       => \$apache_opts,
	'whois-server=s'      => \$whois_server,
	'dns-server=s'        => \$dns_server,
	'whois-cache=s'       => \$whois_cache_file,
	'hide-duplicate-rows' => \$hide_duplicate_rows,
) or pod2usage();

@dns_source or @vhost_source
	or die "Require at least one --dns or --vhost option\n";
exit run();

sub run {
	my @dns_data;
	my @vhost_data;
	
	if ($whois_cache_file) {
		if (-f $whois_cache_file) {
			open(my $fd, '<', $whois_cache_file) or die "open($whois_cache_file): $!";
			while (<$fd>) {
				chomp($_);
				my ($k, @v)= map { lc($_) } split "\t", $_;
				#print STDERR "$k => (".@v.') '.join(', ', @v)."\n";
				$whois_cache{$k}= \@v
					if defined $k and length $k;
			}
		} else {
			open(my $fd, '+>', $whois_cache_file) or die "open($whois_cache_file): $!";
		}
	}

	for my $dns_src (@dns_source) {
		if ($dns_src eq 'mydns') {
			my $home= $ENV{HOME} || '/root';
			dns_merge(\@dns_data, dns_load_dbi("dbi:mysql:mysql_read_default_file=$home/.my.cnf;host=localhost;database=mydns", 'soa'));
		} elsif ($dns_src =~ /^(dbi.*):([^:]+)$/) {
			dns_merge(\@dns_data, dns_load_dbi($1, $2));
		} elsif ($dns_src =~ /^data:(.*)$/) {
			dns_merge(\@dns_data, dns_load_tsv($1));
		} else {
			die "Unrecognized spec for dns data: \"$dns_src\"\n";
		}
	}

	for my $vhost_src (@vhost_source) {
		if ($vhost_src eq 'apache2') {
			vhost_merge(\@vhost_data, vhost_load_apachecfg('/etc/apache2/httpd.conf'));
		} elsif ($vhost_src =~ /^cfg:(.*)$/) {
			vhost_merge(\@vhost_data, vhost_load_apachecfg($1));
		} elsif ($vhost_src =~ /^data:(.*)$/) {
			vhost_merge(\@vhost_data, vhost_load_tsv($1));
		} else {
			die "Unrecognized spec for vhost data: \"$vhost_src\"\n";
		}
	}
	
	if ($dump_vhost) {
		vhost_save_tsv(\@vhost_data, \*STDOUT);
	} elsif ($dump_dns) {
		dns_save_tsv(\@dns_data, \*STDOUT);
	} else {
		my $result= analyze(\@dns_data, \@vhost_data);
		print_analysis($result);
		return 1 if $result->{err};
	}
	return 0;
}

sub dns_merge {
	my ($table1, $table2)= @_;
	# Merge table2 into table1.
	# Assume table1 is sane.
	# Die on conflicting rows, treating domain as primary key.
	# Table format: ( domain, nameserver )
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

sub dns_load_dbi {
	my ($dsn, $table)= @_;
	$cur_nameserver =~ /^[\d\.]+$/
		or $cur_nameserver= dns_resolve($cur_nameserver);
	require DBI;
	my $db= DBI->connect($dsn, undef, undef, { RaiseError => 1, AutoCommit => 1 })
		or die "DBI should have thrown an error";
	my $rows= $db->selectall_arrayref('SELECT origin FROM '.$db->quote_identifier($table), { Slice => [0] });
	for (@$rows) {
		my $d= lc($_->[0]);
		$d =~ s/\.$//;
		$_= { domain => $d, nameserver => $cur_nameserver };
	}
	$rows;
}

sub dns_load_tsv {
	my ($file)= @_;
	my $table= [];
	open(my $fh, "<", $file) or die "open($file): $!";
	<$fh> eq "DOMAIN\tNAMESERVER\n"
		or die "dns tsv file has wrong header\n";
	while (<$fh>) {
		my %row;
		chomp($_);
		@row{'domain','nameserver'}= split '\t', $_;
		push @$table, \%row;
	}
	$table;
}

sub dns_save_tsv {
	my ($table, $fd)= @_;
	print "DOMAIN\tNAMESERVER\n";
	print $fd join("\t", @{$_}{'domain','nameserver'})."\n"
		for @$table;
}

sub apache_dump_vhosts {
	my ($apache_opts)= @_;
	my $out= `apache2 $apache_opts -D DUMP_VHOSTS -t`;
	$out =~ /^Syntax OK$/m
		or die "Can't dump apache options, or configuration syntax error:\n\n$out\n";
	#$out =~ 
	# nevermind
	...
}

sub vhost_merge {
	my ($table1, $table2)= @_;
	# Merge table2 into table1.
	# Assume table1 is sane.
	# die on conflicting rows, treating hostname as primary key.
	# table format: ( hostname, server, site_id )
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
}

# Rudimentary parsing of apache config.  Not intended to be complete
sub vhost_load_apachecfg {
	my ($fname)= @_;
	$cur_webaddr =~ /^[\d\.]+$/
		or $cur_webaddr= dns_resolve($cur_webaddr);
	my @worklist= ($fname);
	my %seen= ($fname => 1);
	my %hostnames;
	while (@worklist) {
		my $f= pop @worklist;
		my $cfg_txt= do { open(my $fh, "<", $f) or die "Can't open $f: $!"; local $/= undef; <$fh> };
		for ($cfg_txt =~ /^\s*Server(?:Name|Alias)\s+(\S+)/mg) {
			next unless $_ =~ /\.\D/;
			$hostnames{$_}= { hostname => lc($_), server => $cur_webaddr, cfg_file => $f };
		}
		push @worklist, grep { !$seen{$_}++ }
			map { index($_, '*') >= 0 ? eval "<$_>" : ($_) }
				($cfg_txt =~ /^\s*Include\s+(\S+)/mg);
	}
	[ values %hostnames ];
}

sub vhost_load_tsv {
	my ($file)= @_;
	my $table= [];
	open(my $fh, "<", $file) or die "open($file): $!";
	<$fh> eq "HOSTNAME\tSERVER\tCFG_FILE\n"
		or die "vhost tsv file has wrong header\n";
	while (<$fh>) {
		chomp($_);
		my %row;
		@row{'hostname','server','cfg_file'}= split '\t', $_;
		push @$table, \%row;
	}
	$table;
}

sub vhost_save_tsv {
	my ($table, $fd)= @_;
	print $fd "HOSTNAME\tSERVER\tCFG_FILE\n";
	print $fd join("\t", @{$_}{'hostname','server','cfg_file'})."\n"
		for @$table;
}

sub dns_resolve {
	my ($host)= @_;
	$host= lc($host);
	return $dns_cache{$host}
		if exists $dns_cache{$host};
	print STDERR "Resolving $host\n";
	my $ip= gethostbyname($host)
		or do { warn "gethostbyname($host): $!"; return '(unresolvable)'; };
	return ($dns_cache{$host}= inet_ntoa($ip));
}

sub whois_resolve {
	my ($domain)= @_;
	$domain= lc($domain);
	#print STDERR "domain = $domain, whois_cache{$domain} = $whois_cache{$domain}\n";
	return [ @{$whois_cache{$domain}} ]
		if exists $whois_cache{$domain};
	my $cust_server= defined $whois_server? "-h $whois_server" : "";
	my $tries= 3;
	while ($tries--) {
		my $out= `whois $cust_server $domain`;
		my @ips= map { lc($_) } ($out =~ /Name Server[^a-zA-Z0-9_\n\r]+(\S+)/mg);
		if ($? != 0) {
			print STDERR "whois error: $out\n";
			sleep 2;
		} else {
			# Look for explicit no-match
			die "Unrecognized output from whois: $out\n"
				unless @ips || ($out =~ /^\s*no match/i);
			print STDERR "whois $domain => ".join(', ', @ips)."\n";
			$whois_cache{$domain}= \@ips;
			if ($whois_cache_file) {
				open(my $fd, ">>", $whois_cache_file) or die "open($whois_cache_file): $!";
				print $fd join("\t", $domain, @ips)."\n";
				close($fd);
			}
			return [ @ips ];
		}
	}
	return [];
}

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
		my $whois= whois_resolve($d);
		my $whois_ip= [ map { dns_resolve($_) } @$whois ];
		# strip trailing dot
		$d =~ s/\.$//;
		#print STDERR "$d ( @$whois_ip ) expect $ip\n";
		$result{domains}{$d}= {
			dns_ip          => $rec->{nameserver} || '',
			dns_official    => $whois,
			dns_official_ip => $whois_ip,
			dns_correct     => !!(grep { $rec->{nameserver} eq $_ } @$whois_ip),
		};
		$result{err_wrong_nameserver}= 1
			unless $result{domains}{$d}{dns_correct};
	}
	for my $rec (@$vhost_data) {
		my $host= lc($rec->{hostname});
		$host =~ /((?:[^.]+.)?[^.]+)$/
			or die "Can't determine domain of hostname \"$host\"\n";
		my $d= $1;
		my $ip= $rec->{server};
		my $actual= dns_resolve($host) || '';
		$result{hosts}{$host}= {
			%$rec,
			domain         => $1,
			hostname       => $host,
			expected_ip    => $ip,
			actual_ip      => $actual,
			ip_correct     => $ip eq $actual,
		};
		$result{err_wrong_webserver}= 1
			unless $result{hosts}{$host}{ip_correct};
	}
	$result{err}= $result{err_wrong_nameserver} || $result{err_wrong_webserver};
	return \%result;
}

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
				: @{$domains->{$d}{dns_official}}? $domains->{$d}{dns_official}[0]
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
