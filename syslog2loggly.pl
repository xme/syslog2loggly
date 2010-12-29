#!/usr/bin/perl
#
# syslog2loggly.pl
# Forward received syslog events to a Loggly Input using HTTPS
#
# Usage: syslog2loggly.pl [-D] [-h] [-p port] [-v] [-f keyfile]
#
# Default configuration file: /etc/syslog2loggly.cong
#   apikey=xxxxx
#   port=xxxxx
#
# Original script: http://wiki.nil.com/Syslog_Server_in_Perl
#
# Note: 
# LWP will support https URLs if the Crypt::SSLeay module is installed.
#

use strict;
use Getopt::Std;
use HTTP::Request::Common qw(POST);
use LWP::UserAgent;
use Net::SSLGlue;
use IO::Socket;
use POSIX qw(setsid);

# We don't care about ended child (to avoid zombies)
$SIG{CHLD} = "IGNORE";

# Variables and Constants
my $MAXLEN  = 1524;
my @facilities = ("kernel", "user", "mail", "daemon", "auth", "syslog", "lpr",
                  "news", "uucp", "cron", "authpriv", "ftp", "local0", "local1",
                  "local2", "local3", "local4", "local5", "local6", "local7");
my @severities = ("emergency", "alert", "critical", "error", "warning", "notice",
                  "info", "debug");

my $buf;
my $pid;
my $rin     = '';
my $daemon  = 0;
my $verbose = 0;
my $port    = 5140;
my $apikey  = '';
my $config  = "/etc/syslog2loggly.conf";
my %opt     = ();

# Process arguments
getopts('Dhvp:f:', \%opt);
if (defined($opt{D})) { $daemon++; }
if (defined($opt{h})) { usage(); }
if (defined($opt{v})) { $verbose++; }
if (defined($opt{p})) {	$port = $opt{p}; }

if (defined($opt{f})) { $config = $opt{f}; }
	
# Read the config file
if (! -r $config) {
	print STDERR "ERROR: Cannot read the configuration file $config.\n";
	exit 1;
}
else {
	open(CONF, "$config");
	while(<CONF>)
	{
		chomp($_);
		$_=~s/\s//g;
		my ($keyword, $value) = split("=", $_);
		$keyword =~ tr/A-Z/a-z/;
		SWITCH: {
			if ($keyword eq "apikey") {
				$apikey = $value;
				last SWITCH;
			}
			if ($keyword eq "port") {
				$port = $value;
				last SWITCH;
			}
		}
	}
	close(CONF);
}
if (length($apikey) != 36) {
	print STDERR "ERROR: Invalid or not found API key. Check loggly.com.\n";
	exit 1;
}
if ($port < 1 || $port > 65535)
{
	print STDERR "ERROR: Invalid port number: $port.\n";
	exit 1;
}

if ($daemon) 
{
	if ($verbose) 
	{
		print STDERR "ERROR: -D and -v options are mutually exclusive.\n";
		exit 1;
	}

	# Detach us
	if (!defined($pid = fork))
	{
		print STDERR "ERROR: Cannot fork. Aborted.\n";
		exit 1;
	}
	exit if $pid;

	if (POSIX::setsid == -1)
	{
		print STDERR "ERROR: setsid: $!\n";
		exit 1;
	}

	if (!chdir("/tmp")) {
		print STDERR "ERROR: Cannot chdir to /tmp.\n";
		exit 1;
	}
	close(STDERR);
	close(STDOUT);
	close(STDIN);
}

# Start Listening on UDP port the given port (default 54100)
($verbose) && print STDERR "Binding to port $port\n";
my $sock = IO::Socket::INET->new(LocalPort => $port, Proto => 'udp')||die("Socket: $@");

($verbose) && print STDERR "Ready to accept events\n";

# ---------
# Main loop
# ---------
while(1)
{
	$sock->recv($buf, $MAXLEN);
	my ($port, $ipaddr) = sockaddr_in($sock->peername);
	my $hn = gethostbyaddr($ipaddr, AF_INET);
	$buf=~/<(\d+)>(.*)/;
	my $pri=$1;
	my $msg=$2;
	my $sev=$pri % 8;
	my $fac=($pri-$sev) / 8;

	# Fork ourself to process the received event
	$pid = fork;
	if ($pid == -1) 
	{
		print STDERR "ERROR: Cannot fork. Aborting.\n";
		exit 1;
	} elsif ($pid) {
		#  We are the parent
		next;
	}
	else {
		# We are the child
		logsys($fac,$sev,$msg);
		exit(0);
	}
}

# Logs Syslog messages
sub logsys
{
	my $facility=shift;
	my $severity=shift;
	my $msg=shift;
        my $maxretries = 3;
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
	$year+=1900; $mon++;
	$msg=~/.*Location: \(.*\) (\d+.\d+.\d+.\d+)/;
	my $ip = $1;
	my $newmsg = sprintf "%04d-%02d-%02dT%02d:%02d:%02d %s facility=%s,severity=%s %s\n", $year, $mon, $mday, $hour, $min, $sec, $ip, $facilities[$facility], $severities[$severity], $msg;
	($verbose) && print STDERR "Message: $newmsg\n";

	while ($maxretries > 0) 
	{
		# Post the event to Loggly
		my $ua = LWP::UserAgent->new(
			agent => 'syslog2loggly.pl');
		my $url = "https://logs.loggly.com/inputs/$apikey";
		my $req = POST $url, 
			Content_Type => 'text/plain',
			Content => $newmsg;
		my $res = $ua->request($req);
		# Template: {"response":"ok"}
		$res->decoded_content=~/\{\"response\":\"(.*)\"\}/;
		if ($1 != "ok") {
			print STDERR "Cannot post event (PID $$). Retrying ...\n";
			sleep(15);
			$maxretries--;
		}
		else {
			# Event successfully sent
			$maxretries=0;
		}
	}
}

sub usage()
{
	print STDERR <<EOF;
syslog2loggly.pl [-f keyfile] [-D] [-h] [-v] [-p port]
  -D          : Run as a daemon
  -h          : This help
  -f keyfile  : Configuration file (default: /etc/syslog2loggly.conf)
  -p port     : Bind to port (default 5140)
  -v          : Increase verbosity
EOF
	exit 1;
}
