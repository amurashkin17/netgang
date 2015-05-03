#!/usr/bin/perl -w

# netgang - provides high availability for heterogeneous network interfaces
#
# Copyright (C) 2015 Alexander Murashkin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

package Gangd;

my($VERSION) = sprintf "%d.%03d", q$Revision: 1.2.1 $ =~ /(\d+)/g; #::

use strict;
#use integer;
use Switch;

use FindBin qw( $Bin $Script );
use Config;
use Sys::Hostname;
use Net::Ping;
use Net::Netmask;
use Time::HiRes     qw( sleep gettimeofday tv_interval );
use Fcntl           qw( :mode O_RDWR O_CREAT F_SETLK LOCK_EX LOCK_UN LOCK_NB );
use Scalar::Util    qw( dualvar);

use threads         qw( stringify );
use threads::shared;
   
my($developerMode);
 
BEGIN {
    if ( $developerMode = $Script =~ /\.pl$/ || $Bin =~ m%/blib/sbin$% ) {
        use lib ($Bin=~/(.*)/,$1) . "/../lib";  # remove $Bin tainteness
    } 
}

use Jlw_common;

my($program)       = $Script;
my($configuration) = "/etc/gang";
my($configPathname);

my($gangName);
my($hostid);

my($workingDir);

my($daemonSystemd) = 0;
my($daemonInitd)   = 0;
my($daemonSelf)    = 0;
my($foreground)    = 0;

my($debugForEach);

my(@gangData);
my($globalOptions);

my($tightSlash)      = dualvar(NO_SEPARATOR,"/");
my($tightApostrophe) = dualvar(NO_SEPARATOR,"'");
my($tightAt)         = dualvar(NO_SEPARATOR,'@');
my($leftPound)       = dualvar(NO_RIGHT_SEPARATOR,"#");
my($separatedAssign) = dualvar(SEPARATOR,":=");

my $readySemaphore  : shared = 2;
my $pingerSemaphore : shared = 0;

sub upSemaphore {

    my($semaphore,$comment)    = @_;
    my($pressOptions) = $debug && pressOptions(PRESS_CALLER => -2);

    lock $$semaphore;
 
    --$$semaphore; cond_broadcast $$semaphore if !$$semaphore;

    printDebug $pressOptions, "upSemaphore", $comment, $separatedAssign, $semaphore if $debug;
}

sub downSemaphore {

    my($semaphore,$comment) = @_;
    my($pressOptions) = $debug && pressOptions(PRESS_CALLER => -2);

    lock $$semaphore;
 
    ++$$semaphore; 

    printDebug $pressOptions, "downSemaphore", $comment, $separatedAssign, $semaphore if $debug;
}

sub waitSemaphore {

    my($semaphore, $comment) = @_;
    my($pressOptions) = $debug && pressOptions(PRESS_CALLER => -2);

    lock $$semaphore; 

    printDebug $pressOptions, "waitSemaphore", $comment, "==", $semaphore if $debug;

    cond_wait $$semaphore while $$semaphore;
}

sub upReadySemaphore {

    upSemaphore   \$readySemaphore, '$readySemaphore';
}

sub waitReadySemaphore {

    waitSemaphore \$readySemaphore, '$readySemaphore'; 
}

sub upPingerSemaphore {

    upSemaphore   \$pingerSemaphore, '$pingerSemaphore';
}

sub downPingerSemaphore {

    downSemaphore \$pingerSemaphore, '$pingerSemaphore';
}

sub waitPingerSemaphore {

    waitSemaphore \$pingerSemaphore, '$pingerSemaphore'; 
}

my $can_flock = 1;      # flock is supported

sub lockInit {

    my($lockname,$timeout,@info) = @_;
    my($pressOptions)            = pressOptions PRESS_CALLER => -2;

    my $lockFH;             # lock filehandle
    my $lockPathname = "";  # lock file pathname
    my $lockResource;       # lock resource name
    my $lockFailfunc;       # \Error, \Warning or empty
    my $lockTimeout  = 0;   # a number of seconds to wait before give up
    my @lockInfo;           # info to put in lock file
    my $lockStart;          # Start time e.g., "Thu Oct 13 04:54:34 1994"
    my $lockProg;           # program name
    my $lockWarnWait = 0;   # how long to wait for the lock before warning

    my($lockdir) = "gang";

    $lockResource = $lockname;

    $lockname =~ s://:/:g; #% # remove extra / 
    $lockname =~ s:^/::;   #%
    $lockname =~ s:/$::;   #%
    $lockname =~ s:%:%%:g; #    replace % with %%
    $lockname =~ s:/:%:g;  #:   replace / with %

    $lockdir  = ( -d "/var/lock" ? "/var/lock/" : "/run/lock/" ) . $lockdir
                unless $lockdir =~ m%^/%;

    $lockPathname = "$lockdir/$lockname";

    -d $lockdir or do {

        mkdir $lockdir                          or Error "Cannot mkdir $lockdir - $!";
        chmod S_IWUSR|S_IRUSR|S_IRGRP, $lockdir or Error "Cannot chmod u=rw,g=r,o= $lockdir - $!";
    };

    $lockStart      = gmtime;
    $lockWarnWait   = 5;
    $lockFailfunc   = \&printError;
    $lockTimeout    = $timeout;
    $lockProg       = $program; $lockProg =~ s%.*/%%g; #%
    @lockInfo       = grep { defined($_) && $_ ne "" } @info;

    if ( $debug ) {

        printDebug $pressOptions, "lockResource", \$lockResource;
        printDebug $pressOptions, "lockTimeout ", \$lockTimeout;
        printDebug $pressOptions, "lockPathname", \$lockPathname;
        printDebug $pressOptions, "lockProg    ", \$lockProg;
        printDebug $pressOptions, "lockInfo    ", \@lockInfo;
    }

    return [ undef, $lockPathname, $lockResource, \@lockInfo, $lockStart, $lockProg, $lockFailfunc, $lockTimeout, $lockWarnWait ];
}

sub lockMyflock {

    my($lockFH,$kind) = @_;

    $can_flock or return 1;

    my $ret = eval "flock( \$lockFH, $kind )";
    if( $@ =~ /unimplemented/ ){
            $can_flock = 0;
            printFatal "flock not available";
    }
    printTrace "flock returned", \$ret if $trace;
    return $ret;
}

sub lockFileObtain   {

    my($lockFH,$lockPathname) = @{$_[0]};

    printTrace "Trying to lock", \$lockPathname, "mode", &LOCK_EX|&LOCK_NB if $trace;
    lockMyflock $lockFH, &LOCK_EX|&LOCK_NB;
}

sub lockFileRelease {

    my($lockFH,$lockPathname) = @{$_[0]};

    Trace "Trying to unlock", \$lockPathname, "mode", &LOCK_UN if $trace;
    lockMyflock $lockFH, &LOCK_UN;
}

sub lockFileReadInfo {

    my($lockFH,$lockPathname) = @{$_[0]};

    seek $lockFH, 0, 0 or printError "Cannot seek", \$lockPathname, ", 0, 0 - $!";

    my $line = <$lockFH>; 
    printTrace "Lockinfo", \$line if $trace;

    my @line = split " ", $line;

    return join(' ',splice(@line,0,5)), @line;
}

sub lockLockWriteInfo {

    my($lockFH,$lockPathname,$lockResource,$lockInfo,$lockStart,$lockProg) = @{$_[0]};

    printDebug  \$lockFH, \$lockPathname, \$lockResource, \$lockInfo, \$lockStart, \$lockProg if $debug;

    my($uid)  = $<;
    my($host) = &hostid();
    my($line) = sprintf "%-511s\n", "$lockStart $$ $host $uid $lockResource $lockProg @$lockInfo";

    my($res);

    $res = sysseek  $lockFH, 0, 0;                 defined($res) or printError "Cannot sysseek",  \$lockPathname, ", 0, 0 - $!";
    $res = syswrite $lockFH, $line, length($line); defined($res) or printError "Cannot syswrite", \$lockPathname, "- $!";
    $res = truncate $lockFH, length($line);        defined($res) or printError "Cannot truncate", \$lockPathname, "- $!";
}

sub lockFileGetInfo {

    my($lstart,$lpid,$lhost,$luid,$lresource,$lprog,@linfo) = lockFileReadInfo $_[0];
    my($lockFH,$lockPathname,$lockResource) = @{$_[0]};

    $lresource eq $lockResource or 
        printError "Lock resource", \$lockResource, "does not match", \$lresource, "in", \$lockPathname;

    my($luser) = getpwuid $luid;

    #$lstart =~ s/\s+\d+$//;

    return $lstart, $lpid, $lhost, $luser, $lprog, @linfo;
}

my %lockActive;

sub getActiveLockFHs {

    my(@fh) = map { $lockActive{$_}[0] } keys %lockActive;

    Debug @fh;

    return @fh;
}

sub lockAcquire {

    my($lock) = lockInit @_;
    my($lockFH,$lockPathname,$lockResource,$lockInfo,$lockStart,$lockProg,$lockFailfunc,$lockTimeout,$lockWarnWait) = @$lock;

    printVerbose "Acquiring lock", \$lockResource if $verbose;

    sysopen  $lockFH, $lockPathname, O_RDWR|O_CREAT, 0660 or
            printError "Cannot open lock file", \$lockPathname, "- $!";
    $| = 1;

    $lock->[0] = $lockFH;

    my $lstart;             # start time of program that has the lock
    my $lhost;              # host --#--
    my $lpid;               # pid --#--
    my $luser;              # username --#--
    my $lprog;              # program name --#--
    my @linfo;              # lock information (arguments, etc) --#--

    my($noted)    = 0;
    my $waittime  = $lockTimeout/50 || 1; $waittime = 15 if $waittime>15;

    for ( my $timeout = $lockTimeout; $timeout>=0; $timeout -= $waittime ) {

            lockFileObtain $lock and do {

                    lockLockWriteInfo $lock;
                    printWarning \$luser, $tightApostrophe, "s", \$lprog, "has completed, running the gang now ..."
                            if $noted;
                    printDebug "Lock", \$lockResource, "succeeded" if $debug;

                    #Debug $_[0][0];
                    $lockActive{$lockResource} = $lock;
                    return 1;
            };

            $timeout>0 or last;

            if ( !$noted && ( $debug || $lockWarnWait && $lockTimeout-$timeout > $lockWarnWait ) ) {

                    ($lstart,$lpid,$lhost,$luser,$lprog,@linfo) = lockFileGetInfo $lock;
                    $lprog =~ s%.*/%%g; #%
                    printWarning "Waiting for", \$luser, $tightApostrophe, "s", \$lprog, "to release", \$lockResource, "(", \$lpid, $tightAt, \$lhost, \$lstart, ")";
                    $noted = 1;
            }

            my $sleep = $waittime<$timeout ? $waittime : $timeout;

            printTrace "Sleeping", $sleep, "seconds" if $trace;
            sleep $sleep;
    }

    printDebug "Lock", \$lockResource, "failed" if $debug;

    if ( $lockFailfunc ) {
        ($lstart,$lpid,$lhost,$luser,$lprog,@linfo) = lockFileGetInfo $lock unless $lstart;
        &$lockFailfunc( \$lockResource, "is locked by", \$luser, $tightApostrophe, "s process", $leftPound, \$lpid, \$lprog, @linfo, "since", \$lstart );
    }

    close $lockFH or printError "Cannot close", \$lockPathname, "- $!";
    $lock->[0] = undef;
    delete $lockActive{$lockResource};

    return 0;
}

sub lockRelease {

    my($lock) = @_;
    my($lockFH,$lockPathname,$lockResource) = @$lock;

    printVerbose "Releasing lock", \$lockResource if $verbose;

    lockFileRelease $lock;

    close $lockFH or printError "Cannot close", \$lockPathname, "- $!";
    $lock->[0] = undef;
    
    delete $lockActive{$lockResource};
}

sub loggingReadConfig {

    #print STDERR 'loggingReadConfig $category ', "gangd", '$confSource ', "/etc/gang/log4perl.conf", "\n";
    logLoadConfig "gangd.config", "/etc/gang/log4perl.conf";
}

sub getOptions {

    $0 = "gangd @ARGV";

    parseOptions [

	    "c|configuration=s"		=> \$configuration,
        "s|systemd"             => \$daemonSystemd,
        "i|initd"               => \$daemonInitd,
        "d|daemon"              => \$daemonSelf,
        "f|foreground"          => \$foreground,

	    #"L|library-path=s"	=> sub { push @libraryPath, split(/:/,$_[1]); },
	    #"l|list-scripts+"	=> \$doListScripts,
	    #"help-datasources" 	=> \$helpAvailableDatasources

    ], [ "logging", "delayed" ];
    
    #$helpInstalledDrivers and helpInstalledDrivers;

    #map { push @inputData, [ "arg",  $_  ] if notEmptyString $_; } @ARGV;
    #push @inputData, [ "file", "-" ] unless @inputData;
    	    
    $daemonSystemd+$daemonInitd+$daemonSelf+$foreground <=1 or
        showUsage "Options --systemd, --initd, --daemon, and --foreground are mutually exclusive";  

	@ARGV <= 1 or
	    showUsage "Only one gang name can be specified";
	    
	$gangName     = $ARGV[0];
	$debugForEach = $trace && \&printTrace;

    if ( $debug ) {

	    printDebug	'$configuration    ', \$configuration;
	    printDebug	'$gangName         ', \$gangName;
    }
}

sub changeWorkingDir {

    Debug "workingDir", $workingDir if $debug;

    chdir $workingDir or Fatal "Cannot change working directory to $workingDir";
}

sub configPathname {

    my($name) = defined($_[0])?$_[0]:$gangName;
    my($conf,$kind) = ! -d $configuration ? ( $configuration,              "e" ) 
                    : defined($name)      ? ( "$configuration/$name.conf", "i" ) 
                    :                       ( "$configuration/gang.conf",  "e" );
    
    if ( $kind eq "i" ) {
        
        -e $conf and return $conf;
        -e "$configuration/gang.conf" or printError "Neither", \$conf, ", nor", \$configuration, "/gang.conf file exists";
        $conf = "$configuration/gang.conf"
    
    } else {
    
        -e $conf or printError "File", \$conf, "does not exist";
    }
    
    -f $conf or printError \$conf, "is not a regular file";
    
    return $conf;
}

sub hostid {

    $hostid = hostname unless $hostid;
    return $hostid;
}

sub currentHostId {

    my($host) = @_;
    my($id)   = hostid;

    $host eq $id and return $host;

    $host !~ /\./ && $id   =~ /^$host\.\S/ and return $id; 
    $id   !~ /\./ && $host =~ /^$id\.\S/   and return $id;

    return ""; 
}

sub recordCaller { 

	return ((caller(5))[3]) ."/". ((caller(4))[3]);
}

sub assertRecord {

    my($record,$recordType) = @_;
    
    ref($record) && ref($record) eq "ARRAY" or 
        printError recordCaller, "- expected an array reference to", \$recordType, "record, got", \$record;
        
    $record->[0] eq $recordType or 
        printError recordCaller, "- got", \$record->[0], "record type instead of expected", \$recordType, ", record is", \$record;
    
    return;
}

sub extractRecord {

    my($record,$recordType,$field) = @_;
    
    assertRecord $record, $recordType;

    #Debug $recordType,$field,":",@$record,"////",@{$record}[1..$#$record];

    return defined($field) ? $record->[$field+1] : @$record[1..$#$record];
}

my($controlType) = 1;
my($floaterType) = 2;
my($hostType)    = 3;
my($gangType)    = 4;
my($fipType)     = 5;
my($devType)     = 6;
my($cipType)     = 7;
my($pingerType)  = 8;

sub controlRecord {

    my($record) = @_;
    
    return extractRecord $record, $controlType;
}

sub controlRecordPingerData {

    my($record) = @_;
    
    return extractRecord $record, $controlType, 3;
}

sub floaterRecord {

    my($record) = @_;
    
    return extractRecord $record, $floaterType;
}

sub hostRecord {

    my($record) = @_;
    
    return extractRecord $record, $hostType;
}

sub fipRecord {

    my($record) = @_;
    
    return extractRecord $record, $fipType;
}

sub pingerRecord {

    my($record) = @_;
    
    return extractRecord $record, $pingerType;
}

sub devRecord {

    my($record) = @_;
    
    return extractRecord $record, $devType;
}

sub cipRecord {

    my($record) = @_;
    
    return extractRecord $record, $cipType;
}

sub gangRecord {

    my($record) = @_;
    
    return extractRecord $record, $gangType;
}

my(@tokens);

sub tokenDesc {

    my($token) = @_;
    return ref($token) ? $token->[1] : $tokens[$token][1];
}

sub tokenWord {

    my($token) = @_;
    return ref($token) ? $token->[3] : $tokens[$token][3];
}

sub tokenRecord {

    my($token) = @_;
    return ref($token) ? @$token : @{$tokens[$token]};
}

my($confLine) = "";
my($th);

sub initToken {

    $th       = $_[0];
    $confLine = "";
}

sub getWord {

    while (1) { 

        if ( $confLine =~ /\s*(\S)(\S*)(.*)$/ && $1 ne "#" ) {

                $confLine = $3;
                return "$1$2";
        }
    
        fileReadline $th or last;
        $confLine = $_;
        #Debug $_;
    }
    
    return "";
}

sub lookupToken {

    my($context,$tokens) = @_;
    
    my($word) = getWord;
    
    $word or return "";
    
    my($token) = $tokens->{$word};
    
    $token or printError "Invalid token", \$word;
    
    my($keyword,$desc,$function,$word1,$allowedContext,$text) = tokenRecord $token;
    
    printTrace \@$context, ":", \$keyword, \$desc,\ $function, \$word1, \$allowedContext, \$text if $trace;
    
    $allowedContext or return $token;
    
    my($requiredContext) = 0;
    foreach my $c ( @$context ) {

        defined $c or next;
        foreach my $f ( @$allowedContext ) {

            if ( $f >= 0 ) {
                ++$requiredContext;
                $c == $f  and return $token;
            } else {
                $c == -$f and printError "Token", \$word, "is not allowed";
            }
        }
    }
    
    !$requiredContext or printError "Unexpected token", \$word;

    return $token;
}

sub lookupValue {

    my($previousToken,$tokens) = @_;
    
    my($word) = getWord;
    
    $word or 
        printError "Missing", tokenDesc($previousToken), "value after", tokenWord($previousToken), "keyword at the file end";
    
    my($token) = $tokens->{$word};
    
    !$token or 
        printError "Missing ".tokenDesc($previousToken)." value between", tokenWord($previousToken), "and", \$word, "keywords";
    
    my($function) = $previousToken->[2];
    
    $function or return $word;
    
    my($value,$error) = @{ &$function($word) };
    
    !$error or 
        printError "Invalid", tokenWord($previousToken), \$word, tokenDesc($previousToken), "value, expected", $error;
    
    return $value;
}

sub checkIP {

    my($ip) = @_;
       
    $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ && $1<256 && $2<256 && $3<256 && $4<256 or
        return [ $ip, "a.b.c.d where a, b, c, d are 0-255" ];
        
    return [ $ip ];
}

sub checkMask {

    my($mask) = @_;
    return [ $mask, $mask =~ /^(\d{1,2})$/ && $1>=1 && $1<=32 ? undef : "n where n is 1-32" ]; 
}

sub checkIPMask {

    my($ipMask) = @_;
       
    $ipMask =~ /^(.*)(\/(.*))?$/;
    my($ip,$mask) = ( $1, $3 );
    
    $ip   = checkIP   $ip;
    $mask = defined($mask) ? checkMask($mask) : [ 30 ];
        
    return $ip->[1] ? $ip : $mask->[1] ? $mask : [ [ $ip->[0], $mask->[0] ] ];
}

sub checkHost {

    my($host) = @_;
    return [ $host, $host =~ /^[a-zA-Z][a-zA-Z0-9.]*$/ ? undef : 
             "an id - a domain name (a sequence of alphanumeric identificators separated by dots)" ]; 
}

sub checkDev {

    my($dev) = @_;
    return [ $dev, $dev =~ /^[a-zA-Z][a-zA-Z0-9]*([.][a-fA-F0-9]+)?(:[a-zA-Z0-9]+)?$/ ? undef : 
             "a, a.n, a:s, a.n:s where a is an alphanumeric identificator, n is a number, s is a label" ]; 
}

sub checkGang {

    my($gang) = @_;
    return [ $gang, $gang =~ /^[a-zA-Z][a-zA-Z0-9]*$/ ? undef : 
             "an alphanumeric identificator (a letter followed by a sequence of letters and digits)" ]; 
}

sub checkSeconds {

    my($seconds) = @_;
    return [ $seconds, $seconds =~ /^(\d*\.)?\d+$/ ? undef : 
             "an integer or floating number of seconds" ]; 
}

my($inGang)     = 1;
my($inHost)     = 2;
my($inFIP)      = 3;
my($inControl)  = 4;

my($gangKeyword)           = 1;
my($hostKeyword)           = 2;
my($fipKeyword)            = 3;
my($devKeyword)            = 4;
my($cipKeyword)            = 5;
my($brdKeyword)            = 6;
my($pingIntervalKeyword)   = 7;
my($floatIntervalKeyword)  = 8;
my($scanIntervalKeyword)   = 9;

my($globalContext) = [ -$inGang, -$inHost, -$inFIP, -$inControl ];

my(%tokens) = (
    
    "gang"           => [ $gangKeyword,          "gang name",             \&checkGang,      undef                  ],
    "host"           => [ $hostKeyword,          "host id",               \&checkHost,      undef, [ $inGang     ] ],
    "fip"            => [ $fipKeyword,           "floating IP[/netmask]", \&checkIPMask,    undef, [ $inHost     ] ],
    "dev"            => [ $devKeyword,           "network device name",   \&checkDev,       undef, [ $inHost     ] ],
    "cip"            => [ $cipKeyword,           "check IP",              \&checkIP,        undef, [ $inHost     ] ],
    "brd"            => [ $brdKeyword,           "broadcast address",     \&checkBroadcast, undef, [ $inFIP      ] ],
    "ping_interval"  => [ $pingIntervalKeyword,  "seconds",               \&checkSeconds,   undef, [ -$inFIP     ] ],
    "float_interval" => [ $floatIntervalKeyword, "seconds",               \&checkSeconds,   undef, [ -$inControl ] ],
    "scan_interval"  => [ $scanIntervalKeyword,  "seconds",               \&checkSeconds,   undef, $globalContext  ],
);

sub initTokenTable {

    map { $tokens[$tokens{$_}[0]] = $tokens{$_}; $tokens{$_}[3] = $_; } keys %tokens;    
}

initTokenTable;

my($currentToken) = undef;
my($currentValue) = "";

my($currentGang);
my($currentHost);
my(@currentCIP,@currentCIPAccumulated);
my(@currentDev,@currentDevAccumulated);
my(@currentFIP);
my(@currentFIPAccumulated);
my(@control);
my(@floaterData);
my(@hostData,%hostData);

my(@parsedOptions);

use constant DEFAULT_OPTIONS => 0;
use constant GANG_OPTIONS    => 1;
use constant HOST_OPTIONS    => 2;
use constant FIP_OPTIONS     => 3;
use constant DEV_OPTIONS     => 4;
use constant CIP_OPTIONS     => 5;

my(@sectionNames);

sub initSectionNames {

    $sectionNames[DEFAULT_OPTIONS] = "default";
    $sectionNames[GANG_OPTIONS]     = $gangKeyword;
    $sectionNames[HOST_OPTIONS]     = $hostKeyword;
    $sectionNames[FIP_OPTIONS]      = $fipKeyword;
    $sectionNames[DEV_OPTIONS]      = $devKeyword;
    $sectionNames[CIP_OPTIONS]      = $cipKeyword;
}

initSectionNames;
 
sub sectionName {

    my($section) = @_;
    my($keyword) = $sectionNames[$section];
    
    return $keyword =~ /^\d/ ? tokenWord($keyword) : $keyword;
}

sub dumpOptions {

    my($pref,$options,$section) = ref($_[0]) ? ( "option",  @_ ) : @_;
    my(@pref)                   = defined($pref) && $pref ne "" ? $pref : ();
    my($pressOptions)           = pressOptions PRESS_CALLER => -1;

    my($was) = 0;

    for ( my $i=0; $i<@$options; ++$i ) { 

        defined $options->[$i] or next;

        printDebug $pressOptions, @pref, sectionName($section) unless !$section || $was++;
        printDebug $pressOptions, @pref, $section ? "----" : (), "[$i]", tokenWord($i), "=", $options->[$i]; 
    } 
}

sub stringOptions {

    my($options) = @_;
    my(@res);

    for ( my $i=0; $i<@$options; ++$i ) { 

        defined $options->[$i] or next;

        push @res, tokenWord($i), $options->[$i]; 
    } 

    return join(" ",@res);
}

sub clearOptions {

    my($maxSection) = @_;

    for ( my $section = $maxSection; $section <= DEV_OPTIONS; ++$section ) {

        $parsedOptions[$section] = [];
    }

    if ( $maxSection != DEV_OPTIONS ) {

        $parsedOptions[CIP_OPTIONS] = [];
    }
}

sub assignOption {

    my($section,$option,$value) = @_;
    $parsedOptions[$section][$option] = $value;
}

sub flattenOptions {

    my($maxSection) = @_;
    my(@options);

    for ( my $section = 0; $section <= $maxSection; ++$section ) {

        my($size) = $parsedOptions[$section] ? scalar(@{$parsedOptions[$section]}) : 0;

        dumpOptions "@", $parsedOptions[$section], $section if $trace && $size;

        for ( my $i=0; $i<$size; ++$i ) { 
            $options[$i] = $parsedOptions[$section][$i] if defined $parsedOptions[$section][$i];
        }
    }

    dumpOptions "#", \@options, $maxSection if $debug;

    return \@options;
}

sub mergeOptions {

    my(@optionSet) = @_;

    my(@options);
    foreach my $options ( @optionSet ) {

        for ( my $i=0; $i<@$options; ++$i ) { 
            $options[$i] = $options->[$i] if defined $options->[$i];
        }
    }

    return \@options;
}

sub optionValue {

    my($options,$keyword,$defaultValue) = @_;

    return defined($options->[$keyword]) ? $options->[$keyword] : $defaultValue;
}

sub currentOptionsSection {

  return    @currentCIP  ? CIP_OPTIONS 
          : @currentDev  ? DEV_OPTIONS
          : @currentFIP  ? FIP_OPTIONS
          : $currentHost ? HOST_OPTIONS
          : $currentGang ? GANG_OPTIONS
          :                DEFAULT_OPTIONS;
}

sub newOption {

    my($option,$value) = @_;

    assignOption  currentOptionsSection, $option, $value;
}

sub parseToken {
    
    return  lookupToken [ @_ ], \%tokens;
}

sub parseValue {
    
    my($previousToken) = @_;
    return  lookupValue $previousToken, \%tokens;
}

sub parseKeyword {

    return parseToken  $currentGang                   && $inGang, 
                       $currentHost                   && $inHost, 
                       @currentFIP                    && $inFIP,
                       ( @currentCIP || @currentDev ) && $inControl;
}

sub parseKeywordValue {

    $currentToken = parseKeyword; $currentToken or return ();
    $currentValue = parseValue $currentToken;
    
    return ( $currentToken->[0], $currentValue );
}

sub finishDEV {

    @currentDev or return;
    
    my($options)  = flattenOptions(DEV_OPTIONS);
    map { $_->[1] = $options } @currentDev;

    push @currentDevAccumulated, @currentDev;

    @currentDev = ();
    clearOptions DEV_OPTIONS;
}

sub finishCIP {

    @currentCIP or return;
    
    my($options)  = flattenOptions(CIP_OPTIONS);
    map { $_->[1] = $options } @currentCIP;

    push @currentCIPAccumulated, @currentCIP;

    @currentCIP = ();
    clearOptions CIP_OPTIONS;
}

sub finishControl {

    finishDEV;
    finishCIP;

    @currentCIPAccumulated || @currentDevAccumulated or return;
    
    push @control, [ $controlType, flattenOptions(HOST_OPTIONS), [ @currentDevAccumulated ], [ @currentCIPAccumulated ], [] ];

    @currentCIPAccumulated = ();
    @currentDevAccumulated = ();
}

sub newCIP {

    my(@cip) = @_;
    
    &finishFIP;
    finishDEV;
    finishControl if @currentCIPAccumulated;
      
    map { push @currentCIP, ( [ $cipType, undef, $_ ] ) } @cip;
}

sub newDev {

    my(@dev) = @_;
    
    &finishFIP;
    finishCIP;
    finishControl if @currentDevAccumulated;
      
    map { push @currentDev, ( [ $devType, undef, $_ ] ) } @dev;
}

sub finishFIP {

    @currentFIP or return;
    
    #Debug @currentFIP;

    my($options)  = flattenOptions(FIP_OPTIONS);
    map { 

        $_->[1] = $options; 
        if ( !defined $_->[4] ) {

            my($net)           = new Net::Netmask "$_->[2]/$_->[3]";    
            $_->[4] = $net->broadcast();
        }

    } @currentFIP;

    push @currentFIPAccumulated, @currentFIP;

    @currentFIP = ();
    clearOptions FIP_OPTIONS;
}

sub newFIP {

    my(@fip) = @_;
    
    finishFIP;
    &finishFloater if @currentCIP || @currentDev;

    map { push @currentFIP, ( [ $fipType, undef, @$_ ] ) } @fip;
}

sub finishFloater {

    @currentFIPAccumulated or return;
    
    finishFIP;
    finishControl;
        
    @control or printError "Missing dev or cip specification";
    
    push @floaterData, [ $floaterType, flattenOptions(HOST_OPTIONS), [ @currentFIPAccumulated ], [ @control ] ];
    
    @control               = ();
    @currentFIPAccumulated = ();
}

sub setBrd {

    my($brd) = @_;
    
    $currentFIP[-1][4] = $brd;
}

sub finishHost {

    $currentHost or return;
    
    finishFloater;
    
    $hostData{$currentHost} and printError "Duplicate", \$currentHost, "host statement in gang", \$currentGang;

    my($adjustedHost) = currentHostId $currentHost;
    #Debug $currentHost, $adjustedHost, $adjustedHost||$currentHost;

    my($hostRecord) = [ $hostType, flattenOptions(HOST_OPTIONS), $adjustedHost||$currentHost, [ @floaterData ] ];
    if ( $adjustedHost ) {
        unshift @hostData, $hostRecord;
    } else {
        push    @hostData, $hostRecord;
    }
    
    $hostData{$adjustedHost||$currentHost} = 1;

    #Debug %hostData;

    @floaterData = ();
    $currentHost = "";

    clearOptions HOST_OPTIONS;
}

sub newHost {

    my($host) = @_;
    
    finishHost if $currentHost;
                
    $currentHost = $host;
}

sub finishGang {

    $currentGang or return;

    finishHost;
    
    #Debug $currentGang, %hostData;
    #Debug $currentGang, hostid(), $hostData{hostid()};

    @hostData           or printError "Gang", $currentGang, "does not have any host statements";
    $hostData{hostid()} or printError "Gang", $currentGang, "does not have this host", hostid, "statement";
    
    push @gangData, [ $gangType, flattenOptions(GANG_OPTIONS), $currentGang, [ @hostData ] ];
    
    #Debug @gangData;

    @hostData    = ();        
    %hostData    = ();
    $currentGang = "";

    clearOptions GANG_OPTIONS;
}

sub newGang {

    my($gang) = @_;
    
    finishGang;
                
    $currentGang = $gang;
}

sub finishConfig {

    finishGang;

    $globalOptions = flattenOptions(DEFAULT_OPTIONS);

    clearOptions DEFAULT_OPTIONS;
}

sub initParser {

    $currentToken           = undef;
    $currentValue           = "";

    @parsedOptions          = ();
    $globalOptions          = undef;
    $currentGang            = undef;

    @hostData               = ();        
    %hostData               = ();
    $currentHost            = undef;
    @floaterData            = ();
    @currentFIP             = ();
    @control                = ();
    @currentFIPAccumulated  = ();
    @currentCIPAccumulated  = ();
    @currentDevAccumulated  = ();
    @currentCIP             = ();
    @currentDev             = ();
}

# gang localIP dev1 remoteIP1 dev2 remoteIP2 ...

# gang GANG
#     hosta HOSTA
#         fipa IPA[/MASKA] 
#         dev1 DEVA1 cip1 IPA1
#         dev2 DEVA2 cip2 IPA2
#     hostb HOSTB
#         fipb IPB[/MASKB] 
#         dev1 DEVB1 cip1 IPB1
#         dev2 DEVB2 cip2 IPB2 

sub parseConfig {

    #Debug "Parsing configuration" if $debug;

    $workingDir = $configuration;    # FIXME
    changeWorkingDir;                # FIXME

    loggingReadConfig;

    $configPathname = configPathname;
    my($ch) = fileOpen( "<" . $configPathname );
    
    initParser;
    initToken $ch;
    
    while ( my($keyword,$value) = parseKeywordValue ) {
    
        printTrace \$keyword, \$value if $trace;

        switch ($keyword) {
        
            case ( $gangKeyword ) { newGang $value; }
            case ( $hostKeyword ) { newHost $value; }
            case ( $fipKeyword  ) { newFIP  $value; }
            case ( $brdKeyword  ) { setBrd  $value; }
            case ( $devKeyword  ) { newDev  $value; }
            case ( $cipKeyword  ) { newCIP  $value; }
            else                  { newOption $keyword, $value; }
        }
    }
    
    finishConfig;
    fileClose $ch;
    
    if ( $debug ) {
      
        my($oldDebug) = $debugForEach;
        $debugForEach = \&printDebug;
        &defaultForEachGang();
        $debugForEach = $oldDebug;
    }
}

my($thisHostRecord);
#my(%thisCIPRecord);
#my(%thisDevRecord);
my(%thisControlRecord);
#my(%thisFloaterRecord);
my($theGangRecord,$theGangName,$theGangNum,$theHostData);
my($theHostRecord,$theHostId,$theFloaterData,$theHostNum);
my($theFloaterRecord,$theFIPData,$theControlData,$theFloaterNum);
my($theFIPRecord,$theFIPAddress,$theFIPMask,$theFIPBrd,$theFIPNum);
my($theControlRecord,$theControlNum,$theDevData,$theCIPData);
my($theDevRecord,$theDevName,$theDevNum);
my($theCIPRecord,$theCIPAddress,$theCIPNum);
my($thePingerRecord,$thePingerIndex,$thePingerNum);

#sub thisCIPRecord {
#
#    return cipRecord $thisCIPRecord{$theFloaterNum}{$theControlNum}{$theCIPNum};
#}
#
#sub thisDevRecord {
#
#    return devRecord $thisDevRecord{$theFloaterNum}{$theControlNum}{$theCIPNum};
#}      

#sub thisFloaterRecord {
#
#    return controlRecord $thisFloaterRecord{$theFloaterNum};
#} 

sub thisControlRecord {

    #Debug %thisControlRecord;
    #Debug "X";
    #map { Debug $_, $thisControlRecord{$_} } sort keys %thisControlRecord;
    #Debug $theFloaterNum, $theControlNum, $thisControlRecord{$theFloaterNum}{$theControlNum};

    return $thisControlRecord{$theFloaterNum}{$theControlNum};
} 

sub typeFunc {

    my($type,$func) = ( shift, shift );
    my($funcType)   = $func && ( ref($func) eq "ARRAY" ? $func->[$type] : $func );

    return $funcType;
}

sub callFunc {

    my($type,$func) = ( shift, shift );
    my($funcType)   = typeFunc $type,$func;

    return $funcType ? &$funcType($func,@_) : 0;
}

sub defaultCIPFunc {

    my($func,$options,$cipNum,$cipRecord,$ip,$pingers,@args) = @_;

    return 1;
}

sub forEachCIP {

    my($func,$cipData,$pingers,@args) = @_;

    typeFunc $cipType, $func or return 1;

    my($cipNum) = 0;
    my($res)    = 1;

    foreach my $cipRecord ( @$cipData ) {
                                  
        my($options,$ip) = cipRecord $cipRecord;   
        ++$cipNum;

        if ( $debugForEach ) {
            &$debugForEach( "          --cip#  ", $cipNum                 );
            &$debugForEach( "            cip   ", \$ip                    );
            &$debugForEach( "            opts  ", stringOptions($options) );
        }

        $theCIPRecord  = $cipRecord;
        $theCIPAddress = $ip;
        $theCIPNum     = $cipNum;

        #$thisCIPRecord{$theFloaterNum}{$theControlNum}{$cipNum} = $cipRecord;

        $res = callFunc $cipType, $func, $options, $cipNum, $cipRecord, $ip, $pingers, @args;
        $res or last;

    } # $cips

    $theCIPRecord  = undef;
    $theCIPAddress = undef;
    $theCIPNum     = undef;

    return $res;
}
   
sub defaultDevFunc {

    my($func,$options,$devNum,$devRecord,$dev,$pingers,@args) = @_;

    return 1;
}

sub forEachDev {

    my($func,$devData,$pingers,@args) = @_;

    typeFunc $devType, $func or return 1;

    my($devNum) = 0;
    my($res)    = 1;

    foreach my $devRecord ( @$devData ) {
                                  
        my($options,$dev) = devRecord $devRecord;   
        ++$devNum;

        if ( $debugForEach ) {
            &$debugForEach( "          --dev#  ", $devNum                 );
            &$debugForEach( "            dev   ", \$dev                   );
            &$debugForEach( "            opts  ", stringOptions($options) );
        }

        $theDevRecord = $devRecord;
        $theDevName   = $dev;
        $theDevNum    = $devNum;

        #$thisDevRecord{$theFloaterNum}{$theControlNum}{$cipNum} = $devRecord;

        $res = callFunc $devType, $func, $options, $devNum, $devRecord, $dev, $pingers, @args;
        $res or last;

    } # $devs

    $theDevRecord = undef;
    $theDevName   = undef;
    $theDevNum    = undef;

    return $res;
}

sub defaultPingerFunc {

    my($func,$options,$pingerNum,$pingerRecord,$pIndex,@args) = @_;

    return 1;
}

sub forEachPinger {

    my($func,$pingerData,@args) = @_;

    typeFunc $pingerType, $func or return 1;

    my($pingerNum) = 0;
    my($res)       = 1;
    
    foreach my $pingerRecord ( @$pingerData ) {
                                  
        my($options,$pIndex) = pingerRecord $pingerRecord;   
        ++$pingerNum;

        if ( $debugForEach ) {
            &$debugForEach( "       --pinger# ", $pingerNum              );
            &$debugForEach( "         pIndex  ", \$pIndex                );
            &$debugForEach( "         opts    ", stringOptions($options) );
        }

        $thePingerRecord = $pingerRecord;
        $thePingerIndex  = $pIndex;
        $thePingerNum    = $pingerNum;

        #$thisDevRecord{$theFloaterNum}{$theControlNum}{$cipNum} = $devRecord;

        $res = callFunc $pingerType, $func, $options, $pingerNum, $pingerRecord, $pIndex, @args;
        $res or last;

    } # $devs

    $thePingerRecord = undef;
    $thePingerIndex  = undef;
    $thePingerNum    = undef;

    return $res;
}

sub thisHost {

    my($hostRecord) = @_;

    return $thisHostRecord == $hostRecord || $thisHostRecord->[2] eq $hostRecord->[2];
}

sub defaultControlFunc {

    my($func,$options,$controlNum,$controlRecord,$devData,$cipData,$pingerData,@args) = @_;

    #Debug "pingerData", $pingerData;

    forEachDev    $func, $devData,    $pingerData, @args;
    forEachCIP    $func, $cipData,    $pingerData, @args;
    forEachPinger $func, $pingerData, @args;

    return 1;
}

sub forEachControl {

    my($func,$controlData,@args) = @_;

    typeFunc $controlType, $func or return 1;

    my($controlNum) = 0;
    my($res)        = 1;

    #Debug "%%%%%%%%%%%%%%%%%%%%%%%%%% Z", @$controlData;

    foreach my $controlRecord ( @$controlData ) {
                       
        my($options,$devData,$cipData,$pingerData) = controlRecord $controlRecord;   
        ++$controlNum;

        if ( $debugForEach ) {
            &$debugForEach(     "    --control#", $controlNum             );
            &$debugForEach(     "      opts    ", stringOptions($options) );
        }

        $theControlRecord = $controlRecord;
        $theControlNum    = $controlNum;
        $theDevData       = $devData;
        $theCIPData       = $cipData;

        $thisControlRecord{$theFloaterNum}{$theControlNum} = $controlRecord if thisHost($theHostRecord); 
        #Debug "%%%%%%%%%%%%%%%%%%%%%%%%%% A", $theFloaterNum, $theControlNum, $thisControlRecord{$theFloaterNum}{$theControlNum} if thisHost($theHostRecord);

        $res = callFunc $controlType, $func, $options, $controlNum, $controlRecord, $devData, $cipData, $pingerData, @args;
        $res or last;

    } # $controls

    $theControlRecord = undef;
    $theControlNum    = undef;
    $theDevData       = undef;
    $theCIPData       = undef;

    #Debug "%%%%%%%%%%%%%%%%%%%%%%%%%% B", %thisControlRecord if thisHost($theHostRecord);

    return $res;
}

#sub forEachControlDataDev {
#
#    my($func,$controlData,@args) = @_;
#
#    my(@func);
#
#    $func[$devType]     = $func;
#    $func[$controlType] = \&defaultControlFunc;
#
#    forEachControl  \@func, $controlData, @args;
#
#    return 1;
#}

sub defaultFIPFunc {

    my($func,$options,$fipNum,$fipRecord,$ip,$mask,$brd,@args) = @_;

    return 1;
}

sub forEachFIP {

    my($func,$fipData,@args) = @_;

    typeFunc $fipType, $func or return 1;

    my($fipNum) = 0;
    my($res)    = 1;

    foreach my $fipRecord ( @$fipData ) {
                              
        my($options,$ip,$mask,$brd) = fipRecord $fipRecord;   
        ++$fipNum;

        if ( $debugForEach ) {
            &$debugForEach(     "        --fip#    ", $fipNum                 );
            &$debugForEach(     "          fip     ", \$ip                    );
            &$debugForEach(     "          mask    ", \$mask                  );
            &$debugForEach(     "          brd     ", \$brd                   );
            &$debugForEach(     "          opts    ", stringOptions($options) );
        }

        $theFIPRecord  = $fipRecord;
        $theFIPAddress = $ip;
        $theFIPMask    = $mask;
        $theFIPBrd     = $brd;
        $theFIPNum     = $fipNum;

        $res = callFunc $fipType, $func, $options, $fipNum, $fipRecord, $ip, $mask, $brd, @args;
        $res or last;

    } # $fips

    $theFIPRecord  = undef;
    $theFIPAddress = undef
    $theFIPMask    = undef;
    $theFIPBrd     = undef;
    $theFIPNum     = undef;

    return $res;
}

sub defaultFloaterFunc {

    my($func,$options,$floaterNum,$floaterRecord,$host,$fipData,$controlData,@args) = @_;

    forEachFIP     $func, $fipData,     @args;
    forEachControl $func, $controlData, @args; 

    #Debug "%%%%%%%%%%%%%%%%%%%%%%%%%% C", %thisControlRecord if thisHost($theHostRecord);

    return 1;
}

sub forEachFloater {

    my($func,$gang,$host,$floaterData,@args) = @_;

    typeFunc $floaterType, $func or return 1;

    my($floaterNum) = 0;
    my($res)        = 1;

    foreach my $floaterRecord ( @$floaterData ) {
     
         ++$floaterNum;
         #Debug  $floaterNum, "floaterRecord", $floaterRecord;

         my($options,$fipData,$controlData) = floaterRecord $floaterRecord;

         if ( $debugForEach ) {
             &$debugForEach(     "  --floater#  ", $floaterNum             );
             &$debugForEach(     "    opts      ", stringOptions($options) );
         }

         $theFloaterRecord = $floaterRecord;
         $theFIPData       = $fipData;
         $theControlData   = $controlData;
         $theFloaterNum    = $floaterNum;

         #$thisFloaterRecord{$theFloaterNum} = $floaterRecord if $theHostRecord == $thisHostRecord; 

         #Debug  $floaterNum, "fipData", $fipData, "controlData", $controlData;

         $res = callFunc $floaterType, $func, $options, $floaterNum, $floaterRecord, $host, $fipData, $controlData, @args;
         $res or last;

    } # $floaterData

    $theFloaterRecord = undef;
    $theFIPData       = undef;
    $theControlData   = undef;
    $theFloaterNum    = undef;

    #Debug "%%%%%%%%%%%%%%%%%%%%%%%%%% D", %thisControlRecord if thisHost($theHostRecord);

    return $res;
}

sub defaultHostFunc {

    my($func,$options,$hostNum,$hostRecord,$gang,$host,$floaterData, @args) = @_;
 
    forEachFloater $func, $gang, $host, $floaterData, @args;
    return 1;
}

sub forEachHost {

    my($func,$gang,$hostData,@args) = @_;

    typeFunc $hostType, $func or return 1;

    my($hostNum) = 0;
    my($res)     = 1;

    $thisHostRecord = $hostData->[0];
    foreach my $hostRecord ( @$hostData ) {
     
        my($options,$host,$floaterData) = hostRecord $hostRecord;
        ++$hostNum;
     
        if ( $debugForEach ) {

           &$debugForEach(                 "   --host#       ", $hostNum                );
           &$debugForEach(                 "     host        ", \$host                  );
           &$debugForEach(                 "     this host   ", thisHost($hostRecord)   );
           &$debugForEach(                 "     opts        ", stringOptions($options) );
           #Debug                 $hostRecord;
           #Debug                 $thisHostRecord;
        }
                
        $theHostRecord  = $hostRecord;
        $theHostId      = $host;
        $theFloaterData = $floaterData;
        $theHostNum     = $hostNum;

        $res = callFunc $hostType, $func, $options, $hostNum, $hostRecord, $gang, $host, $floaterData, @args;
        $res or last;

    } # $hostData
         
    $theHostRecord  = undef;
    $theHostId      = undef;
    $theFloaterData = undef;
    $theHostNum     = undef;
    $thisHostRecord = undef;

    return $res;
}

sub defaultGangFunc {

    my($func,$options,$gangNum,$gangRecord,$gang,$hostData,@args) = @_;
 
    forEachHost $func, $gang, $hostData, @args;
    return 1;
}

sub forEachGang {

    my($func,$gangData, @args) = @_;

    typeFunc $gangType, $func or return 1;

    my($gangNum) = 0;
    my($res)     = 1;

    foreach my $gangRecord ( @$gangData ) {
    
        my($options,$gang,$hostData) = gangRecord $gangRecord;
        ++$gangNum;

        if ( $debugForEach ) {

           &$debugForEach(                 " --gang#         ", $gangNum                );
           &$debugForEach(                 "   gang          ", \$gang                  );
           &$debugForEach(                 "   opts          ", stringOptions($options) );
        }
        
        $theGangRecord = $gangRecord;
        $theGangName   = $gang;
        $theHostData   = $hostData;
        $theGangNum    = $gangNum;

        $res = callFunc $gangType, $func, $options, $gangNum, $gangRecord, $gang, $hostData, @args;
        $res or last;

    } # @gangData

    $theGangRecord = undef;
    $theGangName   = undef;
    $theHostData   = undef;
    $theGangNum    = undef;

    %thisControlRecord = ();
    #Debug "%%%%%%%%%%%%%%%%%%%%%% ***************************************************************";
    #%thisFloaterRecord = ();

    #%thisCIPRecord  = ();
    #%thisDevRecord  = ();

    return $res;
}


sub initForEachFunc {

    my($funcArray,$funcHash) = @_;

    map { $funcArray->[$_] = $funcHash->{$_} } keys %$funcHash 
        unless @$funcArray; 
}

my(%defaultForEachGangFunc) = (

    $controlType  => \&defaultControlFunc,
    $floaterType  => \&defaultFloaterFunc,
    $hostType     => \&defaultHostFunc,
    $gangType     => \&defaultGangFunc,
    $fipType      => \&defaultFIPFunc,
    $pingerType   => \&defaultPingerFunc,
    $devType      => \&defaultDevFunc,
    $cipType      => \&defaultCIPFunc

);

my(@defaultForEachGangFunc);

initForEachFunc  \@defaultForEachGangFunc, \%defaultForEachGangFunc;

sub defaultForEachGang {

    forEachGang  \@defaultForEachGangFunc, \@gangData;

    return 1;
}

sub repeaterInit {

    my($interval) = @_;
    
    return [ $interval,[gettimeofday] ];
}

sub repeaterSleep {

    my($repeater) = @_;
    my($interval,$startTime) = @$repeater;
    
    my($currentTime) = [gettimeofday];
    my($elapsed)     = tv_interval ( $startTime, $currentTime );
    my($waitTime)    = $interval - $elapsed;
        
    if ( $waitTime > 0 ) {
            sleep($waitTime);
            $startTime = [gettimeofday];
    } else {
            $startTime = $currentTime;
    } 
    
    @$repeater = ( $interval,$startTime );
}

sub repeaterTime {

    my($repeater) = @_;
    return $repeater->[1][0] . sprintf(".%6.6d",$repeater->[1][1]);
}

sub waitError {

    if ($? == -1) {
               return "failed to execute: $!\n";
    }
    elsif ($? & 127) {
               return sprintf ( "child died with signal %d, %s coredump\n",
                   ($? & 127),  ($? & 128) ? 'with' : 'without' );
    }
    else {
               return sprintf( "child exited with value %d\n", $? >> 8 );
    }
}
  
sub systemCommand {

    printDebug @_;
    
    my($rc) = system("@_");
    
    $rc == 0 or do {
    
        printError "Cannot run", @_, "-", waitError;  
    };
    
    return !$rc;
}
      
sub addDeviceIP {

    my($gang,$dev,$lIP,$lMask,$lBrd) = @_;

    return systemCommand("ip address add $lIP/$lMask brd $lBrd ldev $dev label $dev:$gang");
}

sub deleteDeviceIP {

    my($gang,$dev,$lIP,$lMask) = @_;
    
    return systemCommand("ip address delete $lIP/$lMask dev $dev");
}

sub updateARPCache {

    my($gang,$dev,$lIP) = @_;

    systemCommand("/sbin/arping -q -A -c 1 -I $dev $lIP");
    sleep(2);
    systemCommand("/sbin/arping -q -U -c 1 -I $dev $lIP"); 
}

my $networkInterfaces : shared;

sub interfaceRecord {

    return @{$_[0]};
}

sub linkRecord {

    return @{$_[0]};
}

sub inetRecord {

    return @{$_[0]};
}

sub equal {

    my($a,$b) = @_;
    return defined($a)&&defined($b) ? $a eq $b : 0
}

sub deviceHasIP {

    my($dev,$lIP,$lMask) = @_;

    my($found) = 0;
    foreach my $interface ( @$networkInterfaces ) {

        my($ifiDevAttrs,$ifiNum,$ifiDev,$ifiFlags,$ifiLinks,$ifiInets) = interfaceRecord $interface;

        #Debug $dev, $ifiDev; #, $ifiInets;

        $dev eq $ifiDev or next;
        
        foreach my $inet ( @$ifiInets ) {

            my($ifiInetAttrs,$ifiInetType,$ifiInetAddress,$ifiInetMask,$ifiInetBroadcast,$ifiInetLabel) = inetRecord $inet;

            #Debug $dev, $ifiDev, $lIP,$ifiInetAddress, $lMask,$ifiInetMask;
            equal($lIP,$ifiInetAddress) && equal($lMask,$ifiInetMask) and do { $found = 1; last; };
        }

        !$found or last;
    }

    printTrace "deviceHasIP", \$dev, \$lIP, $tightSlash, \$lMask, "=>", $found if $trace;

    return $found;
}

my(%ifiDevWords)  = ( "mtu" => 1, "qdisc" => 1, "state" => 1, "group" => 1, "qlen" => 1 ); 
my(%ifiLinkWords) = ( "brd" => 1 ); 
my(%ifiInetWords) = ( "brd" => 1, "scope" => 1, "valid_lft" => 1, "preferred_lft" => 1 ); 

sub parseNetworkAttrs {
    
    my($knownAttrs,$textAttrs,$needLabel) = @_;
    defined($textAttrs) or return {};

    my(@attrs) = split ' ', $textAttrs;
    my(%attrs);
    my($label);

    #Debug @attrs;

    while ( @attrs ) {

        my($a) = shift @attrs;
        my($k) = $knownAttrs->{$a};

        defined $k or do { 

            $attrs{"label"} = $a if $needLabel && !@attrs;
            next; 
        };

        my(@value); push @value, shift(@attrs) while $k--;

        $attrs{$a} = @value == 0 ? 1 : @value == 1 ? $value[0] : [ @value ];
    }

    return \%attrs;
   
}

sub attributesString {

    my($data) = @_;

    return join " ", %$data;
}

sub dumpNetworkInterfaces {

    my($debugFunc,$interfaces) = @_;
    my($pressOptions) = pressOptions PRESS_CALLER => 0;

    &$debugFunc( pressOptions( PRESS_CALLER => -1 ), "Scanned network interfaces" );

    foreach my $interface ( @$interfaces ) {

        my($ifiDevAttrs,$ifiNum,$ifiDev,$ifiFlags,$ifiLinks,$ifiInets) = interfaceRecord $interface;

        &$debugFunc( $pressOptions, sprintf("%-2s",$ifiNum), ":", \$ifiDev, ":", "<", \$ifiFlags, ">", attributesString($ifiDevAttrs) );

        foreach my $link ( @$ifiLinks ) {
            my($ifiLinkAttrs,$ifiLinkType,$ifiLinkAddress,$ifiLinkMask,$ifiLinkBroadcast)= linkRecord $link;
            &$debugFunc( $pressOptions, "    link", $tightSlash, \$ifiLinkType, \$ifiLinkAddress, 
                         (defined($ifiLinkMask)?($tightSlash,\$ifiLinkMask):()),
                         (defined($ifiLinkBroadcast)?("brd",\$ifiLinkBroadcast):()), 
                         " ", attributesString($ifiLinkAttrs)
            );
        }

        foreach my $inet ( @$ifiInets ) {
            my($ifiInetAttrs,$ifiInetType,$ifiInetAddress,$ifiInetMask,$ifiInetBroadcast,$ifiInetLabel) = inetRecord $inet;
            &$debugFunc( $pressOptions, "    ", \$ifiInetType, \$ifiInetAddress, 
                         (defined($ifiInetMask)?($tightSlash,\$ifiInetMask):()),
                         (defined($ifiInetBroadcast)?("brd",\$ifiInetBroadcast):()), 
                         " ", attributesString($ifiInetAttrs), (defined($ifiInetLabel)?\$ifiInetLabel:())
            );
        }
    }
}

# 2: em1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
#    link/ether 50:46:5d:66:57:3c brd ff:ff:ff:ff:ff:ff
#    inet 172.16.0.117/24 brd 172.16.0.255 scope global em1
#       valid_lft forever preferred_lft forever
#    inet6 fe80::5246:5dff:fe66:573c/64 scope link 
#       valid_lft forever preferred_lft forever

sub scanNetworkInterfaces {

    my($first,$options) = @_;
    my($debugFunc) = $first ? $debug && \&printDebug : $trace && \&printTrace; 

    my($ih) = fileOpen "ip addr|", "", \$debugFunc;
    
    my($ifiDevAttrs,$ifiNum,$ifiDev,$ifiFlags,$ifiLinks,$ifiInets);
    my($newNetworkInterfaces);

    while (1) {
    
        my($got) = fileReadline $ih;
        
        !$got || /^(\d+):\s+(\S+):\s+<(\S+)>\s+(.*)$/ and do {

            if ( $ifiNum ) {

                #Debug \@ifiLinks;
                my($r) = [ $ifiDevAttrs, $ifiNum, $ifiDev, $ifiFlags, $ifiLinks, $ifiInets ];

                push @$newNetworkInterfaces, $r;

                $ifiLinks = undef; $ifiInets = undef;
            }

            $got or last;

            $ifiNum = $1; $ifiDev = $2; $ifiFlags = $3; $ifiDevAttrs = parseNetworkAttrs \%ifiDevWords, $4;
            next;
        };

        m%^\s+link\/(\S+)\s+([^/\s]+)(/(\S+))?(\s+(.*))?$% and do {

            my($ifiLinkAttrs) = parseNetworkAttrs \%ifiLinkWords, $6;
            my($brd)          = $ifiLinkAttrs->{"brd"}; delete $ifiLinkAttrs->{"brd"};

            push @$ifiLinks, [ $ifiLinkAttrs, $1, $2, $4, $brd ];
            next;
        };

        m%^\s+(inet(\S*))\s+([^/\s]+)(/(\S+))?(\s+(.*))?$% and do {

            my($inet,$ip,$mask,$attrs)  = ( $1, $3, $5, $7 );
            my($ifiInetAttrs)           = parseNetworkAttrs \%ifiInetWords, $attrs, 1;
            my($brd)                    = $ifiInetAttrs->{"brd"};   delete $ifiInetAttrs->{"brd"};
            my($label)                  = $ifiInetAttrs->{"label"}; delete $ifiInetAttrs->{"label"};

            push @$ifiInets, [ $ifiInetAttrs, $inet, $ip, $mask, $brd, $label ];
            next;
        };
    }
    
    fileClose $ih;

    dumpNetworkInterfaces $debugFunc, $newNetworkInterfaces if $debugFunc;
    
    $networkInterfaces = shared_clone $newNetworkInterfaces;
}

# Body of the floater thread. It periodically calls scanNetworkInterfaces.

sub interfaceScanner {

    my($options) = @_;

    dumpOptions $options if $debug;
        
    my($interval)  = optionValue($options,$scanIntervalKeyword,5); 
    my($repeater)  = repeaterInit $interval;
    my($first)     = 1;

    printVerbose "Running network interface scanner every", \$interval, "seconds" if $verbose;

    while(1) {
    
        scanNetworkInterfaces $first, $options;
        
        if ( $first ) { upReadySemaphore; $first = 0; } 

        repeaterSleep $repeater;
    }
    
}

# Data structure and functions to manipulate pinger's attributes
#   $alive      if last ping is OK
#   $srcDev     source dev
#   $srcIP      source IP
#   $remIP      remote IP

my @pingerState : shared;
my @pingerData  : shared;

my $pingerIndex = 0;

# $alive,$srcDev,$srcIP,$remIP

sub pingerAlive {

    my($pIndex) = @_;
    return $pingerState[$pIndex];
}

sub pingerSetAlive {

    my($pIndex,$alive) = @_;
    $pingerState[$pIndex] = $alive||0;
}

sub pingerAttrs {

    my($pIndex) = @_;
    return $pingerState[$pIndex], @{$pingerData[$pIndex]};
}

sub pingerInit {

    my($pIndex,$alive,$srcDev,$srcIP,$remIP) = @_;

    pingerSetAlive $pIndex, $alive;
    $pingerData[$pIndex] = shared_clone [ defined($srcDev)?$srcDev:"", defined($srcIP)?$srcIP:"", $remIP ];
}

sub pingerDev {

    my($pIndex) = @_;
    return $pingerData[$pIndex][0];
}

# Body of pinger thread. Perioidically pings given remote IP from given 
# source dev and source IP. Updates pinger's status (alive/dead)

sub pinger {

    my($options,$srcDev,$srcIP,$remIP,$pIndex) = @_;
    
    waitReadySemaphore;

    dumpOptions $options if $debug;

    my($interval)  = optionValue $options, $pingIntervalKeyword, 1;
 
    printVerbose "Running", \$srcDev, \$srcIP, "-->", \$remIP, "pinger every", \$interval, "seconds" if $verbose;
   
    my($initial)   = 3;
    my($repeater)  = repeaterInit $interval;
    my($p)         = Net::Ping->new("icmp",$interval);
    
    while(1) {
    
        my($ret,$duration,$ip) = $p->ping($remIP);
        
        pingerSetAlive $pIndex, $ret;
        
        if ( $trace ) {
            printTrace repeaterTime($repeater), "Ping i$initial", \$srcDev, 
                   defined($srcIP)?sprintf("%-15s",$srcIP):undef, "-->", 
                   defined($remIP)?sprintf("%-15s",$remIP):undef, ":", (!$ret?"dead":$ret==1?"alive":"ret".$ret), 
                   defined($duration)?sprintf("%.6f",$duration):undef, 
                   ( defined($ip) && $ip eq $remIP ? () : $ip );
        }

        if ( $initial >= 0 ) {
            $initial-- or do { 
                printDebug "Ping", \$srcDev, \$srcIP, "-->", \$remIP, ": semaphore up" if $debug;
                upPingerSemaphore;
            }
        }

        repeaterSleep $repeater;
    }
    
    $p->close();
}

my($aIndex);        # new active pinger index
my($aDev);          # new active device
my($dIndex);        # pinger that has its device IP removed
my($ok);            # no errors during IP addition/removal
my($needARP);       # if gratious ARP is needed
my($gotActive);     # active device is found

# floaterAddIP moves local IP to given device, if needed
# - if the pinger is dead - nothing happens (and remaing pingers are checked)
# - if the pinger's device is active - nothing happens (but remaining pingers are skipped)
# - otheriwise (the pinger is alive but not active)
# -    if the pinger's device does not have the local IP - the local IP is assigned to the device
# -    skip remaining pingers

sub floaterAddIP {        

    !$gotActive or return 0;
 
    my($func,$pingerOptions,$pingerNum,$pingerRecord,$pIndex,$gang,$sIndex,$sDev,$lIP,$lMask,$lBrd) = @_;

    my($alive,$srcDev,$srcIP,$remIP) = pingerAttrs $pIndex; 

    printTrace "floater", \$gang, "pinger", \$pIndex, ":", \$srcDev, \$srcIP, "-->", \$remIP, "=>", \$alive if $trace;

    $alive or return 1;    # pinger is dead, nothing to do (but check remaing pingers)       

    $gotActive = 1;        # found a device that is already active or will be active

    my($active) = $pIndex == $$sIndex || defined($$sDev) && $srcDev eq $$sDev;

    printTrace "floater", \$gang, "pinger", \$pIndex, ":", \$srcDev, "checking", \$lIP, $tightSlash, \$lMask, "brd", \$lBrd,
       "(", $active, ":", \$pIndex, \$srcDev, ":", $sIndex, $sDev, ")" if $trace;

    $active and return 0;  # pinger's device is still active, nothing to do (skip remaining pingers)

    if ( $$sIndex >= 0 || !deviceHasIP( $srcDev, $lIP,$lMask ) ) {

        if ( $verbose ) {
            printVerbose "floater", \$gang, "pinger", \$pIndex, ":", \$srcDev, "assigning", \$lIP, $tightSlash, \$lMask, "brd", \$lBrd,
                    "(", $active, ":", \$pIndex, \$srcDev, ":", $sIndex, $sDev, ")";
        }

        $ok &= addDeviceIP $gang, $srcDev, $lIP, $lMask, $lBrd;
        $needARP = 1;
    }

    $aIndex    = $pIndex;
    $aDev      = $srcDev;

    return 0;
}

sub floaterDeleteIP {        

    !$ok || !defined($dIndex) or return 0;

    my($func,$pingerOptions,$pingerNum,$pingerRecord,$pIndex,$gang,$sIndex,$sDev,$lIP,$lMask) = @_;

    my($alive,$srcDev,$srcIP,$remIP) = pingerAttrs $pIndex; 

    $pIndex != $aIndex && $srcDev ne $aDev or return 1;

    my($formerActive) = $pIndex == $$sIndex || defined($$sDev) && $srcDev eq $$sDev;
    #$formerActive || $$sIndex < 0 && deviceHasIP( $srcDev, $lIP,$lMask ) or return 1;
    $formerActive || $$sIndex < 0 && deviceHasIP( $srcDev, $lIP ) or return 1;

    printVerbose "floater", \$gang, "pinger", \$pIndex, ":", \$srcDev, "deleting", \$lIP, $tightSlash, \$lMask, "former", \$formerActive if $verbose;

    $ok &= deleteDeviceIP $gang, $srcDev, $lIP, $lMask;
    $needARP = 1;

    $ok     = 0       if defined($dIndex) || !$formerActive;  # not OK if it is a second IP deleting or not active
    $dIndex = $pIndex if $formerActive;

    return !$formerActive || $$sIndex<0;
}

# forEachControlPinger is an utility function that calls given function
# for each pinger in the given controlData

sub forEachControlPinger {

    my($func,$controlData,@args) = @_;

    my(@func);
    $func[$pingerType]  = $func;
    $func[$controlType] = \&defaultControlFunc;

    forEachControl  \@func, $controlData, @args;

    return 1;
}

# processFloaterDevices checks all pingers in controlData (linked to the floater)
# If first alive pinger is active nothing happens, otherwise 
# - the local IP is assigned to the pinger's source device
# - the local IP is removed from the device it was previously assigned to

sub processFloaterDevices {

    my($options,$gang,$lIP,$lMask,$lBrd,$controlData,$sIndex,$sDev) = @_;
    
    $aIndex      = undef;
    $aDev        = undef;
    $dIndex      = undef;
    $ok          = 1;
    $needARP     = 0;
    $gotActive   = 0;
    
    forEachControlPinger \&floaterAddIP,    $controlData, $gang, $sIndex, $sDev, $lIP, $lMask, $lBrd;
    
    defined($aIndex) or return;
    
    forEachControlPinger \&floaterDeleteIP, $controlData, $gang, $sIndex, $sDev, $lIP, $lMask, $lBrd;

    $$sIndex = $ok ? $aIndex : -1;
    $$sDev   = $ok ? $aDev   : undef;

    printTrace "ok", $ok, "sIndex", $sIndex, "sDev", $sDev if $trace;
 
    updateARPCache $gang, $aDev, $lIP if $needARP && $ok;
}

# Body of the floater thread. It periodically checks all pingers linked to 
# the floater, from high to low priority and moves local IP as needed. Actual 
# work is done in processFloaterDevices.

sub floater {

    my($options,$gang,$lIP,$lMask,$lBrd,$controlData) = @_;
        
    waitReadySemaphore;
    waitPingerSemaphore;

    dumpOptions $options, $fipKeyword if $debug;
        
    my($interval)  = optionValue($options,$floatIntervalKeyword,2); 
    my($repeater)  = repeaterInit $interval;
    my($sIndex)    = -1;
    my($sDev)      = undef;
    
    printVerbose "Running", \$gang, \$lIP, $tightSlash, \$lMask, "brd", \$lBrd, "floater every", \$interval, "seconds" if $verbose;

    while(1) {
    
        processFloaterDevices  $options, $gang, $lIP, $lMask, $lBrd, $controlData, \$sIndex, \$sDev;
        
        repeaterSleep $repeater;
    }
    
}

# Launch pinger thread for specific combination of remote IP, 
# source dev, and source IP. Only one thread is lauched for each 
# combination. The pinger thread index is added to the pingerData
# of the current host's controlRecord (this way all pingers are 
# linked to the current host's floater).

my(%ipThread);

sub launchPinger {

    my($optionSet,$thisControlRecord,$srcDev,$srcIP,$remIP) = @_;

    $srcDev = "" unless defined $srcDev;
    $srcIP  = "" unless defined $srcIP;

    my($remOptions,$devOptions,$cipOptions) = @$optionSet;
    my($mergedOptions)                      = mergeOptions($devOptions,$cipOptions);

    if ( $debug ) {
        dumpOptions "devOptions   ", $devOptions if $trace;
        dumpOptions "cipOptions   ", $cipOptions if $trace;
        dumpOptions "mergedOptions", $mergedOptions;
    }

    my($pIndex) = $ipThread{$srcDev,$srcIP,$remIP}; 

    if ( !$pIndex ) {

        $pIndex = $pingerIndex++;
        
        printDebug "Launching", \$srcDev, \$srcIP, \$remIP, "pinger", \$pIndex if $debug;
        
        pingerInit $pIndex, 0,  $srcDev, $srcIP, $remIP;

        downPingerSemaphore;

        my($thread) = threads->create(\&pinger,$mergedOptions,$srcDev,$srcIP,$remIP,$pIndex);
        
        defined($thread) or printError "Cannot launch", \$srcDev, \$srcIP, "-->", \$remIP, "pinger thread - $!";
        
        $ipThread{$srcDev,$srcIP,$remIP} = $pIndex;
    }

    #Debug "thisControlRecord", $thisControlRecord;
    my($pingerData) = controlRecordPingerData $thisControlRecord;

    #Debug $pingerData;

    push @$pingerData, shared_clone([ $pingerType, $mergedOptions, $pIndex ])
        unless grep { $_->[2] == $pIndex } @$pingerData;

    return $pIndex;
}

# Launch floater thread for specific local floating IP/netmask

sub launchFloater {

    my($options,$gang,$lIP,$lMask,$lBrd,$controlData) = @_;
    
    printDebug "Launching", \$gang, \$lIP, $tightSlash, \$lMask, "brd", \$lBrd, "floater" if $debug;
    
    my($thread) = threads->create(\&floater,$options,$gang,$lIP,$lMask,$lBrd,$controlData);
    
    defined($thread) or printError "Cannot launch", \$gang, \$lIP, $tightSlash, \$lMask, "floater thread - $!";
    
    return;
}

# function table for pingerFunc

my(%launchPingerForEachFunc) = (

    $devType      => \&pingerSrcDevFunc,
    $cipType      => \&pingerSrcCIPFunc
);

my(@launchPingerForEachFunc);

initForEachFunc  \@launchPingerForEachFunc, \%launchPingerForEachFunc;

# pingerFunc launches a pinger for each appropriate combination of 
# given remote IP, specified source devs, and specified source IPs. 
# - either srcDev or devData is specified to select one or more source devices  
# - either srcDev or devData is specified to select one or more source devices  
# - remote IP is always given

sub pingerFunc {

    my($optionSet,$remIP,$thisControlRecord,$thisDevData,$thisCipData,$srcDev,$srcIP) = @_;

    #if ( $debug ) {
    #    map { Debug $_ } ( $remIP, $thisControlRecord, $thisDevData, $thisCipData, $srcDev, $srcIP );
    #}

    if ( $thisDevData && @$thisDevData ) {

        forEachDev \@launchPingerForEachFunc, $thisDevData, $thisCipData, $thisControlRecord, $optionSet, $remIP;

    } elsif ( $thisCipData && @$thisCipData )  {

        forEachCIP \@launchPingerForEachFunc, $thisCipData, $thisControlRecord, $optionSet, $remIP, $srcDev;

    } else {

        launchPinger $optionSet, $thisControlRecord, $srcDev, $srcIP, $remIP;
    }

    return 1;
}

# pingerSrcCIPFunc launches a pinger for given combination of 
# remote IP, source dev, and source IP 

sub pingerSrcCIPFunc {

    my($func,$cipOptions,$cipNum,$cipRecord,$srcIP,$thisControlRecord,$accOptions,$remIP,$srcDev) = @_;

    if ( $debug ) {
        #map { Debug $_ } ( $cipNum,$cipRecord,$srcIP,$thisControlRecord,$remIP,$srcDev );
        #Debug $cipOptions, @$accOptions;
    }

    return pingerFunc [ @$accOptions, $cipOptions ], $remIP, $thisControlRecord, undef, undef, $srcDev, $srcIP;
}

# pingerSrcDevFunc launches a pinger for each appropriate 
# combination of given remote IP, given source dev, and possible source IP 

sub pingerSrcDevFunc {

    my($func,$devOptions,$devNum,$devRecord,$srcDev,$thisCipData,$thisControlRecord,$remOptions,$remIP) = @_;

    if ( $debug ) {
        #map { Debug $_ } ( $devNum,$devRecord,$srcDev,$thisCipData,$thisControlRecord,$remIP );
        #Debug $devOptions, $remOptions;
    }

    return pingerFunc [ $remOptions, $devOptions ], $remIP, $thisControlRecord, undef, $thisCipData, $srcDev;
}

# pingerCIPFunc launches a pinger for each appropriate 
# combination of given remote IP and possible source dev and source IP 

sub pingerCIPFunc {

    my($func,$options,$cipNum,$cipRecord,$remIP) = @_;

    #Debug $cipNum,$cipRecord,$remIP;

    !thisHost($theHostRecord) or return 1;

    my($thisControlRecord)        = thisControlRecord;
    #Debug "thisControlRecord", $thisControlRecord;
    my($controlOptions,$thisDevData,$thisCipData) = controlRecord $thisControlRecord;   

    if ( $debug ) {
        #map { Debug $_ } ( $remIP, $thisControlRecord, $thisDevData, $thisCipData );
        #Debug $options;
    }

    return pingerFunc $options, $remIP, $thisControlRecord, $thisDevData, $thisCipData;
}

# launcherFloaterFIPFunc launches a floater for the FIP

sub launcherFloaterFIPFunc {

    my($func,$options,$fipNum,$fipRecord,$ip,$mask,$brd,$controlData,@args) = @_;

    launchFloater $options, $theGangName, $ip, $mask, $brd, $controlData;

    return 1;
}

# launcherFloaterFunc
# - in the case of this host records a floater is launched for each FIP
# - in the case of remote host records pingers are launched for appropriate
#   combinations of source dev, source IP, and remote IP

sub launcherFloaterFunc {

    my($func,$options,$floaterNum,$floaterRecord,$host,$fipData,$controlData,@args) = @_;

    if ( thisHost($theHostRecord) ) {
    
        #Debug "%%%%%%%%%%%%%%%% local host", $host;

        forEachFIP     $func, $fipData, $controlData, @args;
        forEachControl $func, $controlData, @args; 

        return 0; 

    } else {

        #Debug "%%%%%%%%%%%%%%%% remote host", $host;
        #my($thisFloaterRecord) = thisFloaterRecord;
        forEachControl $func, $controlData, @args; 
        return 1;
    }
}

# launchWorker function table is so
# - in the case of this host records a floater is launched for each FIP
# - in the case of remote host records pingers are launched for appropriate
#   combinations of source dev, source IP, and remote IP

my(%launchWorkerForEachGangFunc) = (

    $gangType     => \&defaultGangFunc,
    $hostType     => \&defaultHostFunc,
    $floaterType  => \&launcherFloaterFunc,
    $fipType      => \&launcherFloaterFIPFunc,
    $controlType  => \&defaultControlFunc,
    $cipType      => \&pingerCIPFunc
);

my(@launchWorkerForEachGangFunc);

initForEachFunc  \@launchWorkerForEachGangFunc, \%launchWorkerForEachGangFunc;

# Launch interface scan thread 

sub launchScanner {

    my(@args) = @_;
    
    printDebug "Launching network interface scanner" if $debug;
    
    my($thread) = threads->create(\&interfaceScanner,@args);
    
    defined($thread) or printError "Cannot launch network interface scanner thread - $!";
    
    return;
}

sub launchWorkerThreads {

    launchScanner $globalOptions;

    @gangData = shared_clone @gangData;

    #Debug "%%%%%%%%%%%%%%%%%%%%%%%%%", @gangData;

    forEachGang  \@launchWorkerForEachGangFunc, \@gangData;
}

sub statusUpdate {

    my($flags) = ref($_[0]) ? shift : {};

    if ( $daemonSystemd ) {

        require Systemd::Daemon;

        Systemd::Daemon::notify( %$flags, "STATUS" => "@_" );
    }

    Notice @_;
}

sub determineDaemonKind {

    my($parentPid) = getppid;

    Debug "parentPid", $parentPid;

    if    ( $parentPid != 1     ) { $daemonSelf    = 1; }
    elsif ( $ENV{NOTIFY_SOCKET} ) { $daemonSystemd = 1; Debug "NOTIFY_SOCKET", $ENV{NOTIFY_SOCKET} if $debug; }
    else                          { $daemonInitd   = 1; }
}

sub daemonPidFile {

    my(@pidDirs) = ( "/var/run", "/run", "/tmp" );

    foreach my $d ( @pidDirs ) {

        -d $d and do {

            return "$d/gangd.pid";
        };
    }

    printWarning "Cannot create gang.pid file in @pidDirs as the directories either do not exist or are not accessible";

    return "";
}

sub daemonSelfBecome {

    require Proc::Daemon;

    my($pidFile) = daemonPidFile;

    lockAcquire $pidFile, 3, $gangName if $pidFile;

    my($daemonOptions) = { 

        work_dir      => $workingDir, 
        file_umask    => 026, 
        dont_close_fh => [ getActiveLockFHs ], 
        $pidFile ? ( pid_file => $pidFile ) : ()
    };
    
    pressSuspend;
    logShutdown;

    my($daemonPid) = Proc::Daemon::Init($daemonOptions);

    if ( $daemonPid ) {

        if ( $debug ) {
            pressResume; 
            printDebug "Daemon pid", $daemonPid;
        }

        Exit;
    }

    logStart;
    pressResume;
}

sub daemonStarting {

    determineDaemonKind if $daemonSystemd+$daemonInitd+$daemonSelf+$foreground == 0;

    Debug "kind", $daemonSystemd ? "systemd" : $daemonInitd ? "initd" : $daemonSelf ? "daemon" : $foreground ? "foreground" : undef
        if ( $debug );

    statusUpdate "Starting";
}

sub daemonBecome {

    daemonSelfBecome if $daemonSelf;

    statusUpdate { "READY" => 1 }, "Running scanner, pingers, and floaters";

    upReadySemaphore;
}

sub setup {

    getOptions;

    #print STDERR "setupCall", "\n";
    setupCall [ lc(__PACKAGE__), lc(__PACKAGE__).".config" ], [ [ 1, \&daemonStarting ], [ 2, \&parseConfig, "Parsing configuration" ] ];
}

sub main {

    setup;

    lockAcquire $configPathname, 3, $gangName;

    daemonBecome;

    launchWorkerThreads;

    sleep(60000000);
}

main;
