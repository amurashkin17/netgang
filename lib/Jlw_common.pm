#!/usr/bin/perl -w

# Jlw_common.pm  Common Perl functions 
#
# Copyright (C) 2009-2012 John Lodewright
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

package Jlw_common;

use strict;
use integer;

BEGIN {
	# %EXPORT_TAGS	exported tags, eg: :TAG1 %EXPORT_TAGS = ( TAG1 => [ qw!name1 name2! ], ... )
	# @EXPORT 	    exported by default
    # @EXPORT_OK 	optionally exported  

	use Exporter;
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    $VERSION = sprintf "%d.%02d.%02d", q$Revision: 1.4.3 $ =~ /(\d+)/g; #::

    print STDERR $VERSION, "\n";
    
	@ISA         = qw(Exporter);
    @EXPORT      = qw(
	    parseOptions setupCall showUsage 
	    $quiet $notice $verbose $debug $trace Notice Verbose Warning Error Fatal Debug Trace
        pressEnable pressDisable pressSuspend pressResume pressLevel
        printNotice printVerbose printWarning printError printFatal printDebug printTrace
	    clearErrors haveErrors setErrorFatality
	    Mistake fileOpen fileClose fileSeek fileReadline filePrint filePrintf 
	    Printf 
	    whichPath Exit
        min max trim
	    outputRowBegin outputRowField outputProcess outputPrint outputBegin outputEmptyValue
	    outputHeaderBegin outputHeaderField
	    ioOpen ioClose ioReadline suboptionParse ioPrint ioPrintf
	    ioOptionHelp ioCheckOption
        LEFT_SEPARATOR RIGHT_SEPARATOR SEPARATOR NO_LEFT_SEPARATOR NO_RIGHT_SEPARATOR NO_SEPARATOR
        pressOptions PRESS_LOGGER PRESS_ANGLES PRESS_CALLER
        logStart logShutdown logReadConfig logLoadConfig logDump logPriorities
        PRESS_FATAL PRESS_ERROR PRESS_WARNING PRESS_NOTICE PRESS_VERBOSE PRESS_DEBUG PRESS_TRACE 
	);
    @EXPORT_OK   = qw(
	);
	%EXPORT_TAGS = ( ); 
}

use threads::shared;
use Scalar::Util qw( blessed isdual looks_like_number );
use List::Util   qw( pairmap );
use Getopt::Long;
use Try::Tiny;

use Exception::Class ( "Jlw_common::ErrorException" => { 
                            description => 'Exit called inside first pass of setupCall',
                            fields      => [ 'kind', 'exit_code' ], 
                            alias       => 'throwErrorException' 
} );

use Pod::Usage;
use IO::File;
use IO::Handle;
#use IO::Seekable;
use File::Temp ();
use POSIX qw(WIFEXITED WEXITSTATUS WIFSIGNALED WTERMSIG WIFSTOPPED WSTOPSIG);
use Net::hostent;
use Socket;
#use File::Temp; # qw(tempfile :seekable);
#use File::Temp qw(:seekable);
use Text::CSV;

my($columns);           # screen width or ""
my($htmlViewer);        # HTML viewer name      (if found)
my($htmlViewerPath);    # HTML viewer pathname  (if found)
   
my($help);
my($man);
my($verbosity) = 0;

our($quiet,$notice,$verbose,$debug,$trace);
my($traceFiles,$traceFilenames);

my(%fileAttrs);

my($problems) = 0;
my($errorsFatal) = 1;
my($throwOnExit);

my($log4perlLogger);
my($loggerCategory); 
my($loggerMain);

my(@log4perlLevel);
my(%log4perlLevel);
my $pressLock : shared;

my($stderrLogging)  = -1;
my(@loggingOptions);
my($logInitialized) = 0;
my(@logPass);
my($logMisconfigured);
my($logConfig);
my($onceConfig);
my($loggingEarly);
my($logPriorities);
my($logStore);

my($daemonSystemd) = 0;
my($daemonInitd)   = 0;
my($daemonSelf)    = 0;
my($foreground)    = 0;

use constant PRESS_LOGGER => 1;
use constant PRESS_ANGLES => 2;
use constant PRESS_CALLER => 3;
use constant PRESS_CLASS  => "Jlw_common::Press";

use constant PRESS_FATAL   => 0;
use constant PRESS_ERROR   => 1;
use constant PRESS_WARNING => 2;
use constant PRESS_NOTICE  => 3;
use constant PRESS_VERBOSE => 4;
use constant PRESS_DEBUG   => 5;
use constant PRESS_TRACE   => 6;

sub min {

    my($n);
    map { $n = $_ if defined($_) && ( !defined($n) || $_ < $n ) } @_;
    return $n;
}

sub max {

    my($n);
    map { $n = $_ if defined($_) && ( !defined($n) || $_ > $n ) } @_;
    return $n;
}

sub trim {

    $_[0] =~ s/^\s+//;
    $_[0] =~ s/\s+$//;
}

sub logInit {

    !$logInitialized++ or return;
 
    require Log::Log4perl;
    require Log::Log4perl::Config;
    use if $^C, 'Log::Log4perl::Config';               # to supress compiler error

    Log::Log4perl::Logger::create_custom_level ( "ALERT",  "FATAL", 1, 6 );
    Log::Log4perl::Logger::create_custom_level ( "CRIT",   "ALERT", 2, 5 );
    Log::Log4perl::Logger::create_custom_level ( "NOTICE", "WARN",  5, 2 ); 

    my(@log4perlPriorities) = (

        PRESS_FATAL   ()  => l4p($Log::Log4perl::FATAL), 
        PRESS_ERROR   ()  => l4p($Log::Log4perl::ERROR), 
        PRESS_WARNING ()  => l4p($Log::Log4perl::WARN), 
        PRESS_NOTICE  ()  => l4p($Log::Log4perl::Logger::NOTICE), 
        PRESS_VERBOSE ()  => l4p($Log::Log4perl::INFO), 
        PRESS_DEBUG   ()  => l4p($Log::Log4perl::DEBUG), 
        PRESS_TRACE   ()  => l4p($Log::Log4perl::TRACE) 
    );

    pairmap { $log4perlLevel[$a] = $b->[1]; $log4perlLevel{$b->[0]} = $a; } @log4perlPriorities;
    
    BEGIN {
        local $Log::Log4perl::Logger::NOTICE if $^C;   # to supress compiler error
    }
}

sub logDump {

    my($confData) = @_;

    \&printTrace($confData); 
}

sub logReadConfig {

    my($confSource) = @_;

    logInit;

    my($confData) = ref($confSource) ? $confSource : Log::Log4perl::Config::config_read($confSource);

    logDump $confData if !ref($confSource) && $trace;

    print STDERR "~~~ ", $confSource//"UNDEF", " => ", $confData//"UNDEF", "\n"; 
    
    return $confData;
}

sub l4p {

    my($log4perlLevel) = @_;

    return [ $Log::Log4perl::Level::LEVELS{$log4perlLevel}, $log4perlLevel ];
}

sub logStart {

    my($configFile) = shift;
     
    logInit;

    $configFile = $logConfig unless defined $configFile;
    defined $configFile or &printError( "Log config is not specified" );

    print STDERR "~~~ logStart ", $configFile//"UNDEF", "\n";
    
    eval {
        Log::Log4perl->init( $configFile, logReadConfig($configFile) );
    };
    if ( $@ ) {
        $logMisconfigured = $@;
        &printTrace("Error: $logMisconfigured");
        $logMisconfigured =~ s/\s+at\s+\S+\s+line\s+\d+\.$//;
        return;  
    }
    
    print STDERR "~~~ logStart ", $configFile//"UNDEF", " => ", "OK", "\n";
    
    #Log::Log4perl::init $configFile;

    &printDebug( "Creating loggers", @_ ? ( "explicitly", @_ ) : ( "implicitly", @{$loggerCategory->[1]} ) );

    my($first) = 1;
    foreach my $loggerName ( @_ ? @_ : @{$loggerCategory->[1]} ) { 

        &printDebug( "Creating logger A", $loggerName );

        my($logger) = Log::Log4perl->get_logger($loggerName);

        &printDebug( "Creating logger B", $logger );

        $loggerCategory->[0]{$loggerName} = $logger;
        push @{$loggerCategory->[1]}, $loggerName if @_;

        if ( $first ) {
            $loggerMain     = $loggerName;
            $log4perlLogger = $logger;
            $first          = 1;
            $stderrLogging  = 0 unless $stderrLogging>0;
        }
    } 

    #foreach my $entry ( sort keys %Log::Log4perl::Logger:: )
    #{
    #    print "$entry\n";
    #}


    Log::Log4perl::MDC->put( "SYSLOG_IDENTIFIER", $loggerMain );
    Log::Log4perl::MDC->put( "SYSLOG_FACILITY",   "daemon0"   );
    Log::Log4perl::MDC->put( "SYSLOG_PID",        $$          );

    #print STDERR "logInit ", $configFile, " ", $loggerMain, " \@log4perlLevel\n";
    #print STDERR "log4perlLogger->level ", scalar($log4perlLogger->level()), "\n";
#
    #my($i)=0; map { print STDERR "logInit ", $i++, " : ", $_, "\n" } @log4perlLevel;
}

sub logPriorities {

    $logPriorities = [ map { $Log::Log4perl::Level::LEVELS{$_} } sort { $a+0 <=> $b+0 } keys %Log::Log4perl::Level::LEVELS ]
        unless $logPriorities;

    return $logPriorities;
}

sub logShutdown {

    $log4perlLogger = undef;
    undef ${$loggerCategory->[0]};
}

sub logMessage {

    my($level,$opts) = ( shift, shift );

    #print STDERR "level ", defined($level) ? $level : "UNDEF", " log4perl ", defined($level)&&$log4perlLevel[$level]?$log4perlLevel[$level]:"UNDEF","\n";

    $log4perlLogger->log($log4perlLevel[$level],@_);
}


sub pressLevel {

    logInit;

    #&Debug( $_[0], $log4perlLevel{uc $_[0]} );
    return $log4perlLevel{uc $_[0]};
}

sub pressMessageOut {

    lock $pressLock;

	my($level,$opts,$pref) = ( shift, shift, shift );

    #print STDERR "X ", $log4perlLogger//"UNDEF", "\n"; #/

    print STDERR "${pref}E ", @_, "\n"        if $stderrLogging;

    logMessage $level, $opts, "${pref}L ", @_ if $log4perlLogger; 
}

sub pressMessageData {

    my($level,$opts) = ( shift, shift );

    if ( $logStore ) {

        #print STDERR "S ", @_, "\n";
        push @$logStore, [ $level,$opts, "@{logPass}S", @_ ];

    } else {

        #print STDERR "M ", @_, "\n";

        pressMessageOut $level, $opts, "@{logPass}D", @_;
    }
}

sub pressSuspend {

    $logStore = [] unless $logStore;
}

sub pressResume {

    #print STDERR "pressResume ", '$logStore ', $logStore//"UNDEF", ' $notice ', $notice//"UNDEF", "\n";
 
    $logStore or return;

    my($limitLevel) = PRESS_NOTICE + $notice;

    #print STDERR '$limitLevel', $limitLevel, "\n";

    foreach my $m ( @$logStore ) {

        my($level,$opts) = ( shift(@$m), shift(@$m) );

        #print STDERR "%%% ", $level, " ", @$m, "\n";

        pressMessageOut $level, $opts, @$m if $level <= $limitLevel;
    }

    $logStore = undef;
}

sub formatItem {

	my($opts)        = shift;
    my($pressAngles) = $opts->[PRESS_ANGLES];

    return map { !$pressAngles || !defined($_) ? $_ : $_ eq "" || /\s|[<>{}()]/ ? "<$_>" : $_ } @_;
}

sub arrayDebugRef {

	my($opts) = shift;

    return  map { 
    	    
          !defined($_) 		    ? "UNDEF" 						
        : !ref($_) 			    ? formatItem($opts,$_) 							
        : ref($_) eq "HASH" 	? ( $_, ( %$_ ? ( "{", &arrayDebugRef($opts,%$_), "}" ) : "{}" ) ) 			
        : ref($_) eq "ARRAY" 	? ( $_, ( @$_ ? ( "(", &arrayDebugRef($opts,@$_), ")" ) : "()" ) ) 		
        : ref($_) eq "GLOB" 	? $_ 
   	    : ref($_) eq "CODE" 	? $_ 			
        : 				          formatItem($opts,$_) 
    
	} @_;
}

sub arrayDebug {

	my($opts) = shift;

    return  map { 
    	    
          !defined($_) 		    ? "UNDEF" 						
        : !ref($_) 			    ? $_ 							
        : ref($_) eq "HASH" 	? ( %$_ ? ( "{", &arrayDebug($opts,%$_), "}" ) : "{}" )			
        : ref($_) eq "ARRAY" 	? ( @$_ ? ( "(", &arrayDebug($opts,@$_), ")" ) : "()" ) 		
        : ref($_) eq "GLOB" 	? $_ 
   	    : ref($_) eq "CODE" 	? $_ 		
        : ref($_) eq "SCALAR"	? arrayDebugRef($opts,$$_) 	
        : 				          $_ 
    
	} @_;
}

use constant LEFT_SEPARATOR     => 1;
use constant RIGHT_SEPARATOR    => 2;
use constant NO_LEFT_SEPARATOR  => 4;
use constant NO_RIGHT_SEPARATOR => 8;
use constant NO_SEPARATOR       => NO_LEFT_SEPARATOR | NO_RIGHT_SEPARATOR;
use constant SEPARATOR          => LEFT_SEPARATOR | RIGHT_SEPARATOR;

sub makeSeparator {

    my($opts,$separator,$left,$right) = @_;

    if ( isdual $right ) {

        return ( $right+0 & LEFT_SEPARATOR ) || !( $right+0 & NO_LEFT_SEPARATOR ) ? $separator : "";
    }

    my($r) = substr($right,0,1);
    
    $r =~ /[:,)]/o and return "";    

    if ( isdual $left ) {

        return ( $left+0 & RIGHT_SEPARATOR ) || !( $left+0 & NO_RIGHT_SEPARATOR ) ? $separator : "";
    }

    my($l) = substr($left,-1);

    $l =~ /[(]/o and return "";

    return $separator;
}

sub arrayDebugJoin {

    my($opts,$separator) = ( shift, shift );
    my(@joined);	#    = ( arrayDebug $opts, shift );
    
	map { 

        push @joined, makeSeparator($opts,$separator,$joined[$#joined],$_)
            if @joined && substr($joined[$#joined],-1) ne "\n" && $separator ne "";

        push @joined, $_;
 
    } arrayDebug $opts, @_;
		
	return join "", @joined;
}

sub arrayDebugSplitJoinedLines {

	my($opts) = shift;

    return split /\n/s, arrayDebugJoin($opts," ",@_);
}

sub getOriginalPressOptions {

    my($a)       = @_;
    my($blessed) = blessed($a->[0]);
    if ( defined($blessed) && $blessed eq PRESS_CLASS ) {
        
        return splice @$a, 0, 1; 
          
    } else {

        return [];
    }
}

sub callerFunction { 

	return ( caller(1-($_[0]||0)) )[3];
}

sub pressOptions {
    
    my(@opts);

    foreach my $opt ( @_ ) { 

        if ( !ref($opt) ) {

            if ( !looks_like_number $opt ) {

                $opts[PRESS_CALLER] = $opt;

            } elsif ( $opt > 0 ) {

                $opts[$opt] = 1;

            } elsif ( $opt <= 0 ) {

                $opts[PRESS_CALLER] = $opt ? callerFunction $opt-1 : "";
            }
        }

    };

    return bless \@opts, PRESS_CLASS;
}

sub getPressOptions {

    my($a)       = shift;
    my(@opts)    = @{ getOriginalPressOptions $a };

    map { $opts[$_] = 1 } @_;

    return bless \@opts, PRESS_CLASS;
}

sub arrayTraceLine {

    my($opts) = getPressOptions \@_;

    return "EMPTY" unless @_;

    my($last)=$_[-1];
    $last =~ s/\r/{\\r}/sg;
    $last =~ s/\n/{\\n}/sg;
    $last =~ s/\t/{\\t}/sg;
    $last =~ s/\f/{\\f}/sg;

    return  arrayDebugJoin $opts, '', "<", @_[0..-2], $last, ">";
}

sub printMessage {

	my($level,$prefix) = ( shift, shift );
    my($opts)          = getPressOptions \@_;
    
	$prefix .= " " if $prefix;

	my($i) = 0;
    map { 
	    s/^\s+//; s/\s+$//; pressMessageData $level, $opts, $prefix, $i++?"- ":"", $_ if defined($_) && $_ ne "" 

	} arrayDebugSplitJoinedLines $opts, @_;
}

sub printDebugMessage {

	my($level,$prefix) = ( shift, shift );
    my($opts)          = getPressOptions \@_, PRESS_ANGLES;
    my($caller)        = defined $opts->[PRESS_CALLER] ? $opts->[PRESS_CALLER] : callerFunction(-3);

	$prefix .= " " if $prefix;
	$caller .= " " if $caller;

	my($i) = 0;
    map { 
        s/\s+$//; pressMessageData $level, $opts, $prefix, $caller, $_ if defined($_) && $_ ne "" 

    } arrayDebugSplitJoinedLines $opts, @_;
}


sub setErrorFatality {

	$errorsFatal = $_[0];
}

sub haveErrors {

	return $problems;
}

sub clearErrors {

	$problems = 0;
}

sub pressWarning {

    printMessage PRESS_WARNING, "Warning:", @_;
}

sub Exit {

    pressResume;

    if ( $throwOnExit ) {
    
        throwErrorException "kind" => "exit", "message" => "exit(".($_[0] // 0).") call", "exit_code" => [ @_ ]; #/
    }

    exit @_;
}

sub pressError {
	
    if ( $throwOnExit ) {
    
        throwErrorException "kind" => "error", "message" => \@_; #/
    }

    printMessage PRESS_ERROR, "Error:", @_;
    
    Exit(1) if $errorsFatal;
    ++$problems;
    return undef;
}

sub pressFatal {

    if ( $throwOnExit ) {
    
        throwErrorException "kind" => "fatal error", "message" => \@_; #/
    }

    printMessage PRESS_FATAL, "Fatal:", @_;
    Exit(1);
}

sub pressNotice {

    printMessage PRESS_NOTICE,  "", @_;
}

sub pressVerbose {

    printMessage PRESS_VERBOSE, "", @_;
}

sub pressDebug {

    printDebugMessage PRESS_DEBUG, "---", @_;
}

sub pressTrace {

    printDebugMessage PRESS_TRACE, "===", @_;
}

sub printWarning {

    pressWarning @_;
}

sub printError {
	
    return pressError @_;
}

sub printFatal {

    pressFatal @_;
}

sub printNotice {

    pressNotice @_;
}

sub printVerbose {

    pressVerbose @_;
}

sub printDebug {

    pressDebug @_;
}

sub printTrace {

    pressTrace @_;
}

sub Warning {

    pressWarning    map { \$_ } @_;
}

sub Error {
	
    return pressError map { \$_ } @_;
}

sub Fatal {

    pressFatal      map { \$_ } @_;
}

sub Notice {

    pressNotice     map { \$_ } @_;
}

sub Verbose {

    pressVerbose    map { \$_ } @_;
}

sub Debug {

    pressDebug      map { \$_ } @_;
}

sub Trace {

    pressTrace      map { \$_ } @_;
}

sub Printf {

    #Debug "Printf", @_+0, @_, ";";
    printf arrayDebug(undef,@_) or return Error "Cannot print - $!";
}

# $logConfig hash of hashes
#
#{ 
#        additivity 
#        { 
#                gangd { value 1 } 
#        } 
#        appender { 
#                value Log::Log4perl::Appender::ScreenColoredLevels
#                COLOR { 
#                        stderr    { value 1 } 
#                        Threshold { value TRACE } 
#                        layout    { 
#                                ConversionPattern { value <%d %-5p %c - %m%n> } 
#                                value PatternLayout
#                        }
#                        syswrite { value 1 } 
#                        color { 
#                                DEBUG { value <> } 
#                                ERROR { value magenta } 
#                                FATAL { value red } 
#                                WARN  { value blue }  
#                                INFO  { value green } 
#                                TRACE { value yellow }
#                        }
#                }
#                JOURNAL { 
#                        value Log::Log4perl::Appender::Journald
#                        layout { value Log::Log4perl::Layout::NoopLayout } 
#                }
#                SCREEN { 
#                        value Log::Log4perl::Appender::Screen
#                        Threshold { value INFO }  
#                        layout { 
#                                value PatternLayout
#                                ConversionPattern { value <%d %-5p %c - %m%n> }
#                        }
#                        syswrite { value 1 } 
#                }
#                SYSLOG { 
#                        value Log::Dispatch::Syslog 
#                        layout { value SimpleLayout }  
#                        Facility { value user }  
#                } 
#                SIMPLE_LOGFILE { 
#                        value Log::Log4perl::Appender::File 
#                        syswrite { value 1 } 
#                        mode { value append }  
#                        recreate { value 1 } 
#                        layout { 
#                                value PatternLayout 
#                                ConversionPattern { value <%d{yyyy-MM-dd HH:mm:ss.SSS} %c[%P]: %p{1} %m%n> } 
#                        } 
#                        filename { value /var/log/gangd.log } 
#                        recreate_check_interval { value 60 } 
#                } 
#        } 
#        logger { 
#                gangd { value <DEBUG, SIMPLE_LOGFILE, JOURNAL> } 
#        } 
#        oneMessagePerAppender { value 1 } 
#}

sub loggingConfigRef {

    #printDebug "_", @_;

    my($c) = shift;
    
    foreach my $k ( @_ ) {
        #printDebug "A", $k, %$c;
        my($n) = $c->{$k}; 
        if ( !defined($n) ) {
            my($kk) = lc $k;
            #printDebug "B", $kk;
            $n = $c->{$kk};
            if ( !defined($n) ) {
                foreach my $g ( keys %$c ) {

                    $kk ne lc $g or do { 
                        #printDebug "+", lc($g);
                        $n = $c->{$g}; 
                        last; 
                    };
                    #printDebug "-", lc($g);
                }     
                #printDebug "U", $k;          
            }
            #printDebug "W", $k;          
        } 
        #printDebug "X", $k, \defined($n);
        defined($n) or return $n;
        #printDebug "Y", $k, \defined($n);
        $c = $n;
    }        

    #printDebug ">", $c;
    return $c;
}

sub loggingConfigValue {

    my $r = loggingConfigRef(@_);

    #printDebug ">", $r;

    return $r ? $r->{"value"} : undef;
}

sub loggingLookupRefBreadth {

    my($d,$c) = ( shift, shift );

    ref($c) or return ();

    if ( !$d-- ) {

        my($r) = loggingConfigRef $c, @_; 
        #printDebug "@", $r;
        return $r ? ( $r, [ @_ ] ) : ( undef, undef, 1 );
    
    } else {

        my($f) = 0;
        map {

            #printDebug "#", $_, ":", @_;
            my($r,$p,$x) = &loggingLookupRefBreadth( $d, $c->{$_}, @_ );
            $r and return $r, [ $_, @$p ];
            $f = 1 if $x;

        } sort keys %$c;

        return undef, undef, $f;
    }

}

sub loggingLookupRef {

    my($d) = 0;
    for ( my $d = 0; $d < 100; ++$d ) {
        my($r,$p,$x) = loggingLookupRefBreadth $d, @_;
        $r and return $r,$p;
        $x or  return ();
    }

    printError "Algorithm failure";
}

sub loggingLookupValue {

    my($r,$p) = loggingLookupRef(@_);
    return ( $r ? $r->{"value"} : undef, $p );
}
 
sub loggingGetProperty { 

    my($c) = shift;
    my($v,$p) = loggingLookupValue $c, @_;

    defined($v) or printError "Logging property", join(".",@_), "is not defined";

    printDebug "Logging property get", @$p, "==", $v if $debug;

    return $v;
} 

sub loggingSetPropertyValue {

    my($c,$o,$v) = ( shift, shift, shift );
    my($r,$p)    = loggingLookupRef $c, @_;
    my($newV);

    defined($r) or printError "Logging property", join(".",@_), "is not defined";

    my($oldV) = $r->{"value"};

    if ( $o eq "=" ) {

        $newV = $v;

    } elsif ( $o eq "+" ) {

            $newV = $oldV ? "$oldV, $v" : $v;

    } else {

        if ( defined( $newV = $r->{"value"} ) ) {

            $newV =~ s/^\s*\Q$v\E\s*(,|$)//  or
            $newV =~ s/(^|,)\s*\Q$v\E\s*$//  or
            $newV =~ s/,\s*\Q$v\E\s*,\s*/, /;
        }
    } 

    return $newV, $oldV, $r, $p;
}

sub purifyLoggerProperty {

    my($v,$oldV) = @_;
    my(@r,$priority,%was);
    my($logPriorities) = logPriorities;

    Trace @$logPriorities if $trace;

    foreach my $t ( split /\s*,\s*/, $v ) {

        if ( grep { $t eq $_ } @$logPriorities ) {

            $priority = $t;

        } else {

            !$was{$t} or next;

            $was{$t} = 1;

            push @r, $t;
        }
    }

    if ( !$oldV ) {

        printWarning "Original log specification is not set";

    } elsif ( !$priority || !@r ) {

        #Debug $oldV;

        my(@oldR,$oldPriority);
        foreach my $t ( split /\s*,\s*/, $oldV ) {

            if ( grep { $t eq $_ } @$logPriorities ) {

                $oldPriority = $t;

            } else {

                push @oldR, $t;
            }
        }  

        $priority = $oldPriority unless $oldPriority;
        @r        = @oldR        unless @r;

        $oldPriority or printWarning "Original log specification $oldV does not set priority";
        @oldR        or printWarning "Original log specification $oldV does not set appenders"
    }

    return join( ", ", ( $priority || "NOTICE", @r ? @r : "SCREEN" ) ); 
}

sub loggingSetProperty {

    my($c,$category,$o,$v) = ( shift, shift, shift, shift );

    #printDebug "c", $category, "o", $o, "v", $v, "p", @_;

    my($newV,$oldV,$r,$p) = loggingSetPropertyValue $c, $o, $v, @_;

    if ( defined($newV) ) {

        if ( $_[0] eq "logger" && $_[1] eq $category ) {

            $newV = purifyLoggerProperty $newV, $oldV;
        } 

        $r->{"value"} = $newV;
    }

    printDebug "Logging property set", @$p, ":=", $newV if $debug;
}

sub setLoggingProperties {

    my($c,$category) = ( shift, shift );

    #printDebug @_;
    
    foreach my $prop ( @_ ) {

        #printDebug $prop;

        my($key,$op,$value) = $prop =~ /^(.*?)([-+=])(.*)$/ ? ( $1, $2, $3 ) : ( "", "=", $prop );
   
        trim $key; 
        trim $value; $key or $key = "logger.$category";

        my(@key) = split /\./, $key;

        #printDebug $value, $op, \@key;

        loggingSetProperty $c, $category, $op, $value, @key;
    }
}

sub logLoadConfig {

    my($category,$confSource) = @_;

    print STDERR '~~~ logLoadConfig $category ', $category,' $confSource ', $confSource, ' @loggingOptions ', join("|",@loggingOptions), "\n";
    
    $logConfig = logReadConfig $confSource;

    print STDERR '~~~ logLoadConfig $category ', $category,' $confSource ', $confSource, ' @loggingOptions ', join("|",@loggingOptions), " => ", $logConfig//"UNDEF", "\n";
    
    setLoggingProperties $logConfig, $category, @loggingOptions;

    #printError "ABZAC";
}

sub loggingGetLevel {

    my($globalThreshold)  = loggingConfigValue $logConfig, "threshold";
    my($globalLevel)      = defined($globalThreshold) ? pressLevel($globalThreshold) : PRESS_TRACE;
    my($loggerMaxLevel)   = PRESS_FATAL;
    my(%appenderMaxLevel);

    printDebug '$globalLevel      ', $globalLevel;

    my($loggerNode) = loggingConfigRef $logConfig, "logger";

    for my $loggerName ( "gangd.config" ) {

        my($loggerSpec)       = loggingConfigValue $loggerNode, split( /\./, $loggerName );
        my($appenderMaxLevel) = PRESS_FATAL;
        
        my($loggerLevel);
        my(%appender);

        if ( $loggerSpec ) {
            foreach my $t ( split /\s*,\s*/, $loggerSpec ) {
                my $l = pressLevel($t);
                if ( $l ) { $loggerLevel  = $l; }
                else      { $appender{$t} = 1;  }
            }
        }

        printDebug $loggerName, '$loggerSpec ', $loggerSpec, " : ", $loggerLevel;

        for my $appenderName ( keys %appender ) {

            my($appenderThreshold) = loggingConfigValue $logConfig, "appender", $appenderName, "Threshold";
            #Debug $appenderName, $appenderThreshold;
            my($appenderLevel)     = defined($appenderThreshold) ? pressLevel($appenderThreshold) : PRESS_TRACE;

            printDebug $loggerName, $appenderName, '$appenderLevel', $appenderLevel;

            $appenderMaxLevel = $appenderLevel if $appenderLevel > $appenderMaxLevel;
        }

        $loggerLevel = min $loggerLevel, $appenderMaxLevel;

        printDebug $loggerName, '$loggerLevel', $loggerLevel;

        $loggerMaxLevel = max $loggerLevel, $loggerMaxLevel;
    }

    my($loggingLevel) = min $globalLevel, $loggerMaxLevel;

    printDebug   '$loggerMaxLevel   ', $loggerMaxLevel;
    printNotice  'x                          $loggingLevel     ', $loggingLevel;

    return 6;
    return $loggingLevel;
}

sub exitText {

    my($rc) = @_;

    return  $rc == -1        ? "failed to execute"
    :       WIFEXITED($rc)   ? "exited with code ".WEXITSTATUS($rc)
    :       WIFSIGNALED($rc) ? "killed by signal ".WTERMSIG($rc).($rc&128?" with coredump":"")
    :                          "raw exit code $rc";
}

sub errorMessage {

    return $!               if $!;
    return exitText $?      if $?;
    return "@_"		if @_;

    return "OK";
}

sub fileDescription {

    my($fh,$when) = @_;
    my($attrs) = ref($fh) eq "ARRAY" ? $fh : $fileAttrs{$fh};
    $attrs or $attrs = [ "handler", "file", "", "I/O" ];

    return ($attrs->[5]||$attrs->[0])." $attrs->[1]". ( $when ? " $when " . ($attrs->[2]&&"$attrs->[2] and ") . $attrs->[3] : "" );
}

sub fileIOTrace {

    my($fh,$func) = ( shift, shift );
    my($attrs)   = $fileAttrs{$fh};
    my($iotrace) = $traceFiles || $attrs && $attrs->[6];
    Trace  $func, $attrs?$attrs->[5]||$attrs->[0]:"handle", @_
        if $iotrace;
}

sub fileError {

    my($fh,$action,$when,@msg) = @_;
    #Debug @msg if $debug;
    return printError "Cannot", $action, fileDescription($fh,$when), "-", errorMessage(@msg);
}

sub fileModeRecord {

	my($filename) = @_;
	
	return   $filename =~ /^(\+>)\s*(.*)$/ 	? [ $2,        "file", 		    "",           "reading/writing",	$1    ] 
		   : $filename =~ /^(>>)\s*(.*)$/ 	? [ $2,        "file", 		    "",           "appending",		    $1    ] 
		   : $filename =~ /^(>\+)\s*(.*)$/ 	? [ $2,        "file", 		    "truncating", "reading/writing",	$1    ] 
		   : $filename =~ /^(>)\s*(.*)$/ 	? [ $2,        "file", 		    "truncation", "writing",		    $1    ] 
		   : $filename =~ /^(\|)\s*(.*)$/ 	? [ $2,        "command input", "",           "writing",		    "$1-" ]
		   : $filename =~ /^(.*\S)?\s*(\|)$/? [ $1,        "command output","",           "reading",		    "-$2" ]
		   : $filename =~ /(<)\s*(.*)$/ 	? [ $2,        "file", 		    "",           "reading",		    $1    ] 
		   : 			  	  	              [ $filename, "file", 		    "",           "reading",		    "<"   ];
}

sub fileMode {

	return fileModeRecord(@_)->[4];
}

sub fileModeReading {

	my($mode) = fileMode @_;
	return $mode !~ />\|/;
}

sub fileOptions {

    my(@ioOpts,@tempOpts);
    my($debugFunc) = $debug && \&printDebug;

    while ( @_ ) {

        my($opt)   = shift;
        my($value) = shift;

        if ( ref($opt) ) {

            $opt = $$opt while ref($opt) eq "REF";

            if ( ref($opt) eq "CODE" ) {
                $debugFunc = $opt; 
            } elsif ( ref($opt) eq "SCALAR" ) {
                $debugFunc =
                             defined($verbose) && $opt eq $verbose ? \&printVerbose 
                           : defined($debug)   && $opt eq $debug   ? \&printDebug 
                           : defined($trace)   && $opt eq $trace   ? \&printTrace
                           :                                         undef; 
            }

        } elsif ( ref($value) ) {
            if ( ref($value) eq "CODE" ) {
                $debugFunc = $opt && $value; 
            } else {
                push @ioOpts, [ $opt, $value ];
            }
        } else {
            push @tempOpts, $opt, $value;
        }
    }

    return [ $debugFunc, @ioOpts ], \@tempOpts;
}

sub fileOpen {

	my($filename,$alias,@options) = @_;
	my($needFilename) = wantarray;
	my($fh);
	#Trace "fileOpen", @_, "<", ref($filename) || "noref";
	#Trace @_; # if $trace;

	$filename =~ s/^\s*(\S.*\S)\s*$/$1/;

	# attrs - name, kind, open_action, rw_action, alias, iotrace

	my($attrs) = fileModeRecord $filename;

	if ( $attrs->[0] eq "-" ) {
		$attrs->[0] = $attrs->[3] eq "reading" ? "stdin" : "stdout"; 
		$attrs->[1] = "stream"; 
	}
 
	push @$attrs, $alias, $traceFiles || $traceFilenames && ( $traceFilenames->{$attrs->[0]} || $traceFilenames->{$filename} || $traceFilenames->{$alias||""} || $traceFilenames->{$_[0]} );
		
	#Debug @$attrs;

    my($ioOpts,$tempOpts) = fileOptions @options;
    my($debugFunc)        = @$ioOpts;

	if ( $attrs->[0] ) {

		$fh = new IO::File $filename;

	} else {
		$fh = new File::Temp UNLINK => !$needFilename, @$tempOpts;
		$attrs->[0] = $filename = $fh->filename;
		$attrs->[1] = "temporary " . $attrs->[1];
	}

	defined($fh) or return fileError $attrs, "open", "for";

    if ( $debugFunc ) {
	    #Trace @_; # if $trace;
	    &$debugFunc( $debug ? \@_ : (), "- Opened", ( $attrs->[5] ? \$attrs->[6] : \$attrs->[0] ), $attrs->[1], "for", 
            $attrs->[2]?\$attrs->[2]:(), $attrs->[2]&&$attrs->[3]?"and":(), 
            $attrs->[3]?\$attrs->[3]:(), $attrs->[6]&&"(with iotrace)"||()
        );
    }

	$fileAttrs{$fh} = $attrs;
	return $needFilename ? ( $fh, $filename ) : $fh;  
}

sub fileClose {

    my($fh) = @_;
    close $fh or return fileError $fh, "close", "after";
    fileIOTrace $fh, "fileClose", "- OK" if $trace;
    delete $fileAttrs{$fh};
    return 1;
}

sub fileSeek {

	my($fh,$pos,$whence) = @_;
	seek $fh,$pos,$whence or return fileError $fh, "seek $pos $whence";
	fileIOTrace $fh, [ "fileSeek", $pos, $whence ], "- OK" if $trace;
	return 1;
}

sub fileGetline {

        my($fh,$buffer) = @_;

        !defined($buffer) || ref($buffer) eq "SCALAR"or
                Fatal "fileGetline second is defined but not as reference to SCALAR";

        my($internalBuffer);
        my($refBuffer) = $buffer || \$internalBuffer;

        $$refBuffer = $fh->getline;
        !$fh->error or return fileError $fh, "read";

        fileIOTrace $fh, "fileGetline", ">", defined($$refBuffer)?"OK ":"EOF", defined($$refBuffer)?arrayTraceLine($$refBuffer):"UNDEF"
                if $traceFilenames;

        return !$buffer ? $internalBuffer : defined($$buffer);
}

sub fileReadline {

        my($fh,$buffer) = @_;
        return fileGetline $fh, $buffer||\$_;
}

sub filePrint {

        my($fh) = shift;

        fileIOTrace $fh, "filePrint", "<", arrayTraceLine(@_) if $traceFilenames;

        print $fh @_ or return fileError $fh, "write";
        return 1;
}

sub filePrintf {

        my($fh) = shift;

        fileIOTrace $fh, "filePrintf", "<", arrayTraceLine(@_) if $traceFilenames;

        printf $fh @_ or return fileError $fh, "write";
        return 1;
}

#sub Capitalize {
#
#	my($text) = arrayDebugJoin(undef," ",@_);
#	$text =~ s/^\s*(-\s*)?//;
#	return $text =~ /^(\S)(.*)$/ ? uc($1).$2 : $text;
#}

#sub ErrorC {
#
#	Error Capitalize(@_);
#}

sub Mistake {

        if ( ref $_[0] ) {
                my($fh) = shift;
                return Error @_, "-", fileDescription($fh), ", line", $fh->input_line_number;
        } else {
                return Error @_;
        }
}

sub preprocessText {

	my($text,$textOnly) = @_;

	return $text if !$textOnly;

	$text =~ s/<[^>]*>/ /g;
	$text =~ s/\s+/ /g;
	$text =~ s/(^\s|\s$)//g;

	return  "$text\n";
}

sub catPod {

        my($fd,$file,$prefix,$textOnly,@sections) = @_;

        my($in) = fileOpen "<${file}", "script";

        my(%sections);
        my($print) = !@sections;
        map { $sections{$_}=1 } @sections;

        while (fileReadline $in) {

                /^=head\d\s+(\S.*\S)\s*$/ and do {

                        $print = !@sections || $sections{$1};
                        filePrint $fd, $prefix, $_ if $print && !$textOnly;
                        next;
                };

                $textOnly && /^\s*$|^=/ and next;
                filePrint $fd, $prefix, preprocessText($_,$textOnly) if $print;
        }

        fileClose $in;
}

sub printDoc {

        my($output,$prefix,$textOnly,@sections) = @_;
        my($fd);

        if ( ref($output) ) {
                $fd = $output;
        } else {
                #print STDERR "@@@ $output\n";
                $fd = fileOpen "|set -o pipefail; $output", "doccmd";
        }

        catPod  $fd, $0, $prefix, $textOnly, @sections;

        if ( !ref($output) ) {
                fileClose $fd;
        }
}

sub getColumns {

        return $columns if $columns;

        $columns = $ENV{"COLUMNS"};
        return $columns if $columns;

        $columns = "";
        return $columns unless -t STDOUT;

        my($sttyOutput) = `stty -a`;
        $columns = $1 if $sttyOutput =~ /;\s+columns\s+(\d+);/;

        return $columns;
}

sub columnsOption {

        my($opt) = @_;
        getColumns;
        return $columns ? " $opt $columns " : ""
}



sub whichPath {

        my($command) = @_;
        my($whichOutput) =`which $command 2>/dev/null`;
        chomp $whichOutput if $whichOutput;
        return $whichOutput;
}

sub findHtmlViewer {

        foreach my $viewer ( "w3m", "lynx", "elinks" ) {
                $htmlViewer     = $viewer;
                $htmlViewerPath = whichPath $htmlViewer;
                #print STDERR "@@@ <$htmlViewer> <$htmlViewerPath>\n";
                return if $htmlViewerPath;
        }
        Fatal "Cannot find HTML viewer";
}

sub viewerCommand {

        my($viewers) = @_;
        findHtmlViewer;
        #print STDERR "@@@ <$htmlViewer> <$htmlViewerPath>\n";

        my($command) = $viewers->{$htmlViewer};
        $command =~ s/$htmlViewer/$htmlViewerPath/;
        if ( $command =~ /^(.*)\[(.*)\$columns(.*)](.*)$/ ) {
                getColumns;
                $command = $columns ? "$1$2$columns$3$4" : "$1$4";
        }
        $command =~ s/\s+$//;
        return $command;
}

my(%helpViewer) = (

        "elinks" => 'elinks -default-mime-type text/html -dump -no-numbering -no-references [-dump-width $columns]',
        "lynx"   => 'lynx -stdin -dump -nolist [-width=$columns]',
        "w3m"    => 'w3m -T text/html -dump [-cols $columns]'
);

my(%manualViewer) = (

        "elinks" => 'elinks -default-mime-type text/html',
        "lynx"   => 'lynx -stdin',
        "w3m"    => 'w3m -T text/html'
);


sub showHelp {

        my($generator) = "pod2html --noindex|sed -e 's%<h1>%<h1 align=left>%'|grep -v '^<hr />\$'";

        printDoc "$generator|".viewerCommand(\%helpViewer), "", 0, "NAME", "SYNOPSIS", "OPTIONS", "ARGUMENTS";
        Exit(0);
}


sub showManual {

        my($generator) = "pod2html |sed -e 's%<li><a%<a%' -e s'%a></li>%a>%' -e 's%<h1>%<h1 align=left>%' |awk '/^<!-- INDEX BEGIN/{i=1}/^<!-- INDEX END/{i=0}/^<ul>\$/{if(!i)print;else print \"<b>Sections</b> \"; next}/^<[/]ul>\$/{if(!i)print; next}{print}'";

        printDoc  "$generator|".viewerCommand(\%manualViewer), "", 0;
        Exit(0);
}

sub showUsage {

        print STDERR "Error: ", join(" ",grep{$_}@_), "\n" if @_;
        printDoc  *STDERR{IO}, "Usage: ", 1, "SYNOPSIS";
        Exit(2);
}

sub pressEnable {
    
    #print STDERR "x ", join(",",map{defined($_)?$_:"UNDEF"}@_), "\n";

    my($r,$level,$print) = @_ >= 2 || ref($_[0]) ? @_ : ( undef, @_ );

    #print STDERR "r ", defined($r)?join(",",map{defined($_)?$_:"UNDEF"}@$r):"none", " l ", defined($level)?$level:"UNDEF", "\n";

    defined($r) || defined($level) or return;

    ( $verbosity, $traceFilenames ) = @$r if defined $r;

    $verbosity = $level >= PRESS_NOTICE() ? $level-PRESS_NOTICE() : 0 if defined($level);

    $quiet	        = $verbosity<0  ? $verbosity : 0;
    $notice         = $verbosity>=0 ? $verbosity : 0;
    $verbose        = $verbosity>0  ? $verbosity : 0;
    $debug          = $verbosity>1  ? $verbosity : 0;
    $trace          = $verbosity>2  ? $verbosity : 0 ;
    $traceFiles     = $verbosity>3  ? $verbosity : 0;
    $traceFilenames = {} if $traceFiles && !$traceFilenames;

    if ( 1 ) { #FIXME $print && $debug ) {

        printDebug   callerFunction(-1);
        printDebug   '$quiet         ',  $quiet;
        printDebug   '$notice        ',  $notice;
        printDebug   '$verbose       ',  $verbose;
        printDebug   '$debug         ',  $debug;
        printDebug   '$trace         ',  $trace;
        printDebug   '$traceFiles    ',  $traceFiles;
        printDebug   '$traceFilenames',  $traceFilenames;
    }
}

sub pressDisable {

    my($r) = [ $verbosity, $traceFilenames ];

    pressEnable [ -10, undef ], undef, 0;

    return $r;
}

my($pressConfig);

sub pressDelay {

    if ( !$loggingEarly ) {

        @logPass = ("1");
        
        pressSuspend;
        pressEnable PRESS_TRACE;
    }
}

sub pressRestrict {

    $pressConfig = !$onceConfig && pressDisable;
}

sub pressAllow {

    my($loggerNames) = @_;
    my($logLevel)    = loggingGetLevel;
    #print STDERR "logLevel", defined($logLevel)?$logLevel:"UNDEF", "\n";

    pressEnable $pressConfig, $logLevel;

    logStart undef, defined($loggerNames) ? @$loggerNames : ();

    pressResume unless $loggingEarly;
    
    @logPass = ("2");
}

my($calledFuncDesc);

sub callFuncList {

    my($pass,$func) = ( shift, shift );

    #print STDERR "callFuncList _ ", $func, "\n";

    if ( ref($func) eq "CODE" ) {

        #print STDERR "callFuncList A ", $func, "\n";
        &$func(@_);

    } else {

        foreach my $f ( @$func ) {

            #print STDERR "callFuncList B ", $f, "\n";

            if ( ref($f) eq "CODE" ) {
                &$f(@_);          
            } elsif ( ref($f->[0]) ) {
                $pass == 1 or next;
                &{$f->[0]}(@_);
            } else {
                $pass <= $f->[0] or next;
                printDebug $f->[2], $f->[0]<=1 ? () : $pass == 1 ? "(first pass)" : "(second pass)" if $debug && $f->[2];
                $calledFuncDesc = $f->[2];
                &{$f->[1]}(@_);
            }
        }
    }
}

sub setupCallFirstPass {

    my($a) = [ @_ ];

    if ( $onceConfig ) {

        callFuncList @$a;

    } else {

        try {

            $throwOnExit = 1;
            Jlw_common::ErrorException->NoContextInfo(1);

            callFuncList @$a;

        } catch {

            $throwOnExit = 0;
            my($errorException) = blessed $_ && $_->isa("Jlw_common::ErrorException");

            #print STDERR "!!! ", $_, "\n";
            #print STDERR "!!! ", blessed($_), "\n";
            #print STDERR "!!! ", blessed($_), ' $errorException ', $errorException, "\n";
            my($kind,$message);

            if ( !$errorException ) {

                printMessage PRESS_TRACE, "Error:", $_;
                $message = $_;
                $kind    = "unexpected error";

            } else {

                ($kind,$message) = ( $_->kind(), $_->message() );
                $kind = "" if $kind eq "exit";

                printMessage PRESS_TRACE, "Error:", ref($message)?@$message:$message if $kind;
            }               

            printDebug $calledFuncDesc, "at first pass aborted due to an", $kind?($kind,"-"):(), ref($message)?@$message:$message;
        };

        $throwOnExit = 0;
    }
}

sub setupCallSecondPass {

    callFuncList @_ unless $onceConfig;
}

sub setupCall {

    my($loggerNames,$func) = ( shift, shift );

    #print STDERR "setupCall [ ", @$loggerNames, " ] ", $func, "\n";

    pressRestrict;
    setupCallFirstPass  1, $func, @_;
    pressAllow          $loggerNames;
    setupCallSecondPass 2, $func, @_;
    
    !$logMisconfigured or printError $logMisconfigured;
}

sub parseOptions {

    my($appOptions,$appStdOptions) = @_;
    my($stdOptions) = {};

    map { $stdOptions->{$_} = 1 } @$appStdOptions  if ref($appStdOptions) eq "ARRAY";
    $stdOptions = $appStdOptions                   if ref($appStdOptions) eq "HASH";

    my($needLog)     = $stdOptions->{"logging"};
    my($needDaemon)  = $stdOptions->{"daemon"};
    my($needDelayed) = $stdOptions->{"delayed"};

    $onceConfig = !$needDelayed;

    pressDelay unless $onceConfig;

    my($savedWARN) = $SIG{"__WARN__"};
    $SIG{"__WARN__"} = sub { print STDERR "Error: @_"; };

    Getopt::Long::Configure ("bundling");
    my(@iotrace);

    $quiet  = 0;
    my($ok) = GetOptions (
              
        @$appOptions,
        "q|quiet+"          => \$quiet,               
        "v|verbose+"        => \$verbosity,               
        "h|help|?"          => \$help,                   
        "m|man"             => \$man,                       
        "T|iotrace=s"       => \@iotrace,
        $needLog ? (
            "l|log=s"       => \@loggingOptions,
            "E|stderr"      => sub { $stderrLogging = ($stderrLogging>0?$stderrLogging:0)+1 },
        ) : (),   
        $needDaemon ? (
            "s|systemd"     => \$daemonSystemd,
            "i|initd"       => \$daemonInitd,
            "d|daemon"      => \$daemonSelf,
            "f|foreground"  => \$foreground,
        ) : ()
    );

    $SIG{"__WARN__"} = $savedWARN;

    map { $traceFilenames->{$_}=1 if $_ } split(/,/,join(",",@iotrace));

    $verbosity = ( $verbosity||0 ) - $quiet if $quiet;
    pressEnable [ $verbosity, $traceFilenames ], undef, 1;

    showUsage  if !$ok;
    showHelp   if $help;
    showManual if $man;
}

sub parseParameters {

        parseOptions   @_;
	#parseArguments @_;
}

my(@output);
my(@header);
my(@needColumn);
my($emptyValueString) = "-";
my($emptyValueNumber) = 0;

sub outputBegin {

        @output = ();
	@header = ();
}

sub outputRowX {

        push @output, [ @_ ];
}

sub outputRowBegin {

	push @output, [ map { [ $_, $_ ] } @_ ];
}

sub outputRowField {

	my($field,$value,$sortValue) = @_;
	#print STDERR "[$#output][$field] $value\n";
        $output[-1][$field] = [ $value, defined($sortValue)?$sortValue:$value ];
}

sub outputHeaderX {

        push @header, [ @_ ];
}

sub outputHeaderBegin {

	push @header, [ @_ ];
}

sub outputHeaderField {

	my($field,$value) = @_;
	#print STDERR "[$#header][$field] $value\n";
        $header[-1][$field] = $value;
}

sub traceOutput {

	my($r) = @_;
	Trace map { if(ref $_){ $_->[0],$_->[1]} else {$_,"x"}} @{$r};
}

sub outputProcess {	# for example, sort

        my($func) = @_;
	my(@res);
	#map { Trace map { if(ref $_){ $_->[0],$_->[1]} else {$_,"x"}} @{$_} } @output;
	foreach my $s ( &$func(@output) ) {
	
		push @res, [ map { ref $_ ? $_->[0] : $_ } @{$s} ];
	}

	#map { Trace map { if(ref $_){ $_->[0],$_->[1]} else {$_,"x"}} @{$_} } @output;
	#map { Trace $_ } @res;
	#map { Trace "A",@{$_} } @res;

	@output = @res;
}

sub outputPrintf {

	my($fh,$format,$l) = ( shift, shift, shift );
	#Trace $format, $l, arrayDebugAngled("a",@_);
	my(@a);
	#map { push @a, $_ if defined $_ } @_[1..$#_];

	for ( my $i=1; $i<@_; $i++ ) {

	    $needColumn[$i] or next;
	    my($v) = $_[$i];
            push @a, defined($v) ? $v : $l->[$i] ? $emptyValueString : $emptyValueNumber;
        }

	#ioPrintf $fh, "$format\n", @a;

	&ioPrintf( $fh, $format, \@a );
}

sub outputEmptyValue {

	 ( $emptyValueString, $emptyValueNumber ) = @_ == 0 ? ( "-", "0" ) : @_ == 1 ? ( $_[0], $_[0] ) : @_;
	 
	 Debug "emptyValueString", $emptyValueString if $debug;
 	 Debug "emptyValueNumber", $emptyValueNumber if $debug;
}

sub outputPrint {

	@output or return;

        my($newLineFunc,$file) = @_;
        
        my($fh) 	= ref($file) ? $file : ioOpen( "text", ">" .($file||"-") );
        my($formatted) 	= ioType($fh) eq "text";
        
	#Debug $file, $fh;

        my(@format,$i);
        my(@w,@l);
        my($fn);

	# Calculate columns width based on the header cells
	
        map {
            $fn = @$_;
            for ( $i=1; $i < $fn; $i++ ) {
		defined($_->[$i]) or next;
                $w[$i] = length($_->[$i])
                        if !$w[$i] || $w[$i] < length($_->[$i]);
            }
        } @header;

       	# Adjust columns width and figure out column type based on the data cells

        map {
            $fn = @$_;
            for ( $i=1; $i<$fn; $i++ ) {
		defined($_->[$i]) or next;
		$needColumn[$i]=1;
                $l[$i] |= $_->[$i] =~ /\D/;
                $w[$i] = length($_->[$i])
                        if !$w[$i] || $w[$i] < length($_->[$i]);
            }
        } @output;

        # Fill header - cells 
        
        map {
            $fn = @$_;
            for ( $i=1; $i<$fn; $i++ ) {
		defined($_->[$i]) or next;
                $_->[$i] = "-" x $w[$i] if $_->[$i] eq "-";
            }
        } @header;

        # Construct format
        
        my($wcount,$wsize) = ( 0, 0 );
       
        for ( $i=1; $i<@w; $i++ ) {
	    $needColumn[$i] or next;
            push @format, "%" . ($l[$i]?"-":"") . "$w[$i]s";
            $wsize += $w[$i];
            ++$wcount;
        }

	Debug "Format @format" if $debug;

	#Debug $file, $fh;
	my($underline) = &ioOptionValue( $fh, "underline" );
	my($underText);
	
	if ( $underline ) {
	
	 my($sep)  = &ioOptionValue( $fh, "separator" ); $sep = " " unless defined $sep;
	 
	 $wsize += (($wcount||1)-1)*length($sep);
	 $wsize += 2*length($sep) if $sep !~ /^\s+$/;
	 
	 $underText = ( "-" x $wsize ) . "\n";
	}
	
	# Print header lines
	
	&ioPrint( $fh, $underText ) if $underline;

        map { outputPrintf $fh, \@format, \@l, @$_ } @header;

       	&ioPrint( $fh, $underText ) if $underline;

        # Print data lines
        
        map {
        
	  if ( @$_ > 1 ) {
	  
                &ioPrintf( $fh, "\n" ) if defined($newLineFunc) && &$newLineFunc(@$_);
		push @$_, undef while @$_ < @w;
		outputPrintf $fh, \@format, \@l, @$_;
		
	  } else {
	  
		if ( $underline ) {
		
		  &ioPrint( $fh, $underText );
		  
		} else {
		
		  &ioPrintf( $fh, "\n" );
		}
	  }
	  
        } @output;

       	&ioPrint( $fh, $underText ) if $underline;

        &ioClose( $fh ) unless ref($file);
}

sub wordAdd {

	my($words,$word) = @_;
	
	!$words->{$word} or return;
	
	for ( my $i=1; $i<=length($word); ++$i ) {
	    my($s) = substr($word,0,$i);
	    my($r) = $words->{$s};
	    $r or $words->{$s} = $r = [];
	    push @$r, $word;
    	    #Debug '$r', $r, '$s', $s, '$word', $word, @$r;
	}
	push @{$words->{""}}, $word;
}

sub wordFind {

	my($words,$subword) = @_;
	
	Trace '$subword', $subword, '$words->{$subword}', $words->{$subword} if $trace;

	return !wantarray ? $words->{$subword} : defined($words->{$subword}) ? @{$words->{$subword}} : ();
}

sub wordLookup {

	my($words,$subword,$desc,$must) = @_;
	my(@found) = wordFind $words, $subword;
	
	@found || $must>0 or return ( undef, $words->{""} );
	
	@found      		or showUsage "Invalid $desc '$subword' (not one of " . join(" ",sort @{$words->{""}}) . ")";
	@found == 1 || $must<0 	or showUsage "Ambiguous $desc '$subword' matches " . join(", ", @found);
	 
	return ( $found[0], $words->{""} );
}

my(%csvHelp,@csvHelp,%csvWords);
my(@csvDesc) = (

	'eol'			=> [ *Text::CSV::eol, 			"s", "rw", '??? An end-of-line string to add to rows. C<undef> is replaced with an empty string. The default is C<$\>.' ],
	'sep_char'		=> [ *Text::CSV::sep_char, 		"c", "rw", 'The character used for separating fields, by default a comma (C<,>).' ],
	'allow_whitespace'	=> [ *Text::CSV::allow_whitespace, 	"b", "r",  "Remove whitespace (TABs and SPACEs) surrounding the separation character" ],
	'blank_is_undef'	=> [ *Text::CSV::blank_is_undef, 	"b", "r",  'Causes unquoted empty fields to be read as undef' ],
	'empty_is_undef'	=> [ *Text::CSV::empty_is_undef, 	"b", "r",  'Any empty field is read as undef' ],
	'quote_char'		=> [ *Text::CSV::quote_char, 		"c", "rw", 'The character used for quoting fields containing blanks, by default the double quote character(C<">).' ],
	'allow_loose_quotes'	=> [ *Text::CSV::allow_loose_quotes, 	"b", "r",  'Allow C<quote_char> characters inside a field' ],
	'escape_char'		=> [ *Text::CSV::escape_char, 		"c", "rw", 'The character used for escaping certain characters inside quoted fields, by default a the literal double-quote mark (C<">)' ],
	'allow_loose_escapes'	=> [ *Text::CSV::allow_loose_escapes, 	"b", "r",  'Allow C<escape_char> characters that escape characters that do not need to be escaped' ],
	'binary'		=> [ *Text::CSV::binary, 		"b", "r",  'Allow binary characters in quoted fields, including line feeds, carriage returns and NULL bytes' ],
	'always_quote'		=> [ *Text::CSV::always_quote, 		"b", "w",  'All defined fields will be quoted even if they need not to' ],
	'quote_space'           => [ *Text::CSV::quote_space, 		"b", "w",  'Quote fields containing spaces (default)' ],
	'quote_null'		=> [ *Text::CSV::quote_null, 		"b", "w",  'NULL bytes in a field would be escaped (default)' ],
	'quote_binary'          => [ *Text::CSV::quote_binary, 		"b", "w",  'Quote fields containing "unsafe" bytes >= 0x7f (default)' ],
	'verbatim'		=> [ *Text::CSV::verbatim, 		"b", "r",  'Treat newline (NL) and carriage return (CR) as ordinary binary characters' ],
	'field-separator'	=> 'sep_char'
);

my(%csvDesc);

sub commonDescInit {

	my($words,$hashDesc,@desc) = @_;
	
	for ( my $i=0; $i<@desc; $i+=2 ) {
	    #$desc[$i+1][0] = eval $desc[$i+1][0];
	    if ( ref $desc[$i+1] ) {
		$hashDesc->{$desc[$i]} = $desc[$i+1];
		$desc[$i+1][0] = $desc[$i];
	    } else {
		$hashDesc->{$desc[$i]} = $hashDesc->{$desc[$i+1]};
	    }
	    wordAdd $words, $desc[$i];
	}
	
	#Debug '$desc{"sep_char"}', $desc{"sep_char"};
}

sub commonCheckOption {

	my($hashDesc,$hashWords,$subword,$desc,$must) = @_;
	
	my($item,$all) = wordLookup $hashWords, $subword, $desc, $must;
	return ( $item, defined($item) ? $hashDesc->{$item} : undef, $all );
}

sub commonOptionHelp {

	my($arrayHelp,$hashHelp) = @_;
	
	foreach my $item ( @$arrayHelp ) {
	  
	    print STDOUT "$item\n";
	    map { print STDOUT "    $_\n" } @{$hashHelp->{$item}};
	}
}

sub commonFileOpenOptions {

	my($commDesc,$commOpts,$fileOpts,@options) = @_;
		
	@options = map { ref($_) ? %$_ : $_ } @options;
	Trace "all options", @options if $trace;

	while ( @options ) {
	  
	  my($opt,$val) = ( shift @options, shift @options );
	  #Debug "src options", $opt, $val;

	  if ( $commDesc->{$opt} ) { push @$commOpts, $opt, $val; }
	  else                     { push @$fileOpts, $opt, $val; }	  
	}
	
	Trace "comm options", @$commOpts if $trace;
	Trace "file options", @$fileOpts if $trace;

	return;
}

sub csvGetOptions {
	
	my($fh) = fileOpen $INC{"Text/CSV.pm"};
	
	my($inNew,$item);
	while ( fileReadline $fh ) {
	
	    /^=head\d*\s+new/ 	and do { $inNew = 1; next; };
	    !$inNew		and next;
	    
   	    /^=(head|back)/	and last;
	    /^=item\s+(\S+)/ 	and do { $item = $1; push @csvHelp, $item; wordAdd \%csvWords, $item; next; };
	    $item 		and do { chomp; push @{$csvHelp{$item}}, $_; next; }; 
	}
	
	fileClose $fh;
	
	map { push @{$csvDesc{$_}}, $csvHelp{$_} } keys %csvHelp;
	
	Debug '@csvHelp', @csvHelp if $debug;
	return [ \%csvHelp, \@csvHelp ];
}


sub csvDescInit {

	my $csv = Text::CSV->new ( { binary => 1 } );
	$csv->eof;
	
	commonDescInit \%csvWords, \%csvDesc, @csvDesc;

	Debug '$csvDesc{"sep_char"}', $csvDesc{"sep_char"};
	Debug '$csvDesc{"field-separator"}', $csvDesc{"field-separator"};

	csvGetOptions;
}

sub csvCheckOption {

	my($subword,$desc,$must) = @_;
	
	%csvDesc or csvDescInit;

	return  commonCheckOption \%csvDesc, \%csvWords, $subword, $desc, $must;
}

sub csvOptionHelp {

	%csvDesc or csvDescInit;
	
	commonOptionHelp \@csvHelp, \%csvHelp;
}

sub csvFileOpen {

	my($filename,$alias,@options) = @_;

	%csvDesc or csvDescInit;
	
	my(@fileOpts,@csvOpts);
	commonFileOpenOptions  \%csvDesc, \@csvOpts, \@fileOpts, @options;
	
	Debug "csv options", @csvOpts;
	my $csv = eval { Text::CSV->new ( { @csvOpts } ) }  
	    or Error "Cannot use CSV: ".Text::CSV->error_diag();
	
	my($mode) = fileModeReading($filename) ? "r" : "w";
	my($fh)   = fileOpen( "$filename", $alias, @fileOpts );
	
	Debug '$fh', $fh, '$csv', $csv, '$mode', $mode;
	return [ $fh, { @csvOpts }, $csv ];
}

my(%csvErrors) = ( 

	"4004 EUF -"	=> "escape character is outside quoted fields",
);

sub csvFileReadline {

        my($ch,$buffer) = @_;
        my($fh,$copts,$csv) = @$ch;
       	Debug '$fh', $fh, '$csv', $csv;

       	#my $line = <$fh>; $fh or die "FAILED $!";
       	#Debug '$line', $line;
       	#exit;
       	
       	undef $!;
        my($row) = $csv->getline( $fh );
        
        $row || $csv->eof or do {
	    my($cde,$str,$pos) = $csv->error_diag;
	    $str =~ s/\s+/ /; $str =~ s/( $)|(^ )//g; 
	    fileError $fh, "parse", "", "CSV record " . ($csv->record_number+1) . ", position $pos, " .
		     ( $csvErrors{"$cde $str"} ? "$cde $str " . $csvErrors{"$cde $str"} : "error $cde $str" );
        };
        
        $$buffer = $row;
        
        Debug $row, ( $row ? @$row : () ) if $debug;
        return $row;
}

sub csvFilePrintf {
	
	my($ch,$format) = ( shift, shift );
        my($fh,$copts,$csv) = @$ch;
       	Debug '$fh', $fh, '$csv', $csv;

       	@_ = map { ref($_)?@$_:$_ } @_;
       	
       	if ( ref($format) ) { 
	  for ( my $i=0; $i < @_ && $i < @$format; ++$i ) {
	  
	    $_[$i] = sprintf $format->[$i], $_[$i];
	  }
	} 
	
       	undef $!;
        my($status) = $csv->combine(@_);
                
        $status or do {
	    my($cde,$str,$pos) = $csv->error_diag;
	    fileError $fh, "print", "", "CSV record " . ($csv->record_number+1) . ", position $pos, error $cde $str";
        };
        
        return filePrint $fh, $csv->string, "\n";
}

sub csvFilePrint {
	
	my($ch) = ( shift );
	
	return csvFilePrintf $ch, undef, @_;
}

sub csvFileClose {

        my($ch,$buffer) = @_;
        my($fh,$copts,$csv) = @$ch;
        
        return fileClose $fh;
}

my(%textHelp,@textHelp,%textWords);
my(@textDesc) = (

	'eol'			=> [ undef, "s", "rw", '??? An end-of-line string to add to rows. C<undef> is replaced with an empty string. The default is C<$\>.' ],
	'separator'		=> [ undef, "s", "rw", 'The string used for separating fields, by default a space (C< >).' ],
	'allow_whitespace'	=> [ undef, "b", "r",  "Remove whitespace (TABs and SPACEs) surrounding the separation character" ],
	'blank_is_undef'	=> [ undef, "b", "r",  'Causes unquoted empty fields to be read as undef' ],
	'empty_is_undef'	=> [ undef, "b", "r",  'Any empty field is read as undef' ],
	'quote_char'		=> [ undef, "c", "rw", 'The character used for quoting fields containing blanks, by default the double quote character(C<">).' ],
	'allow_loose_quotes'	=> [ undef, "b", "r",  'Allow C<quote_char> characters inside a field' ],
	'escape_char'		=> [ undef, "c", "rw", 'The character used for escaping certain characters inside quoted fields, by default a the literal double-quote mark (C<">)' ],
	'allow_loose_escapes'	=> [ undef, "b", "r",  'Allow C<escape_char> characters that escape characters that do not need to be escaped' ],
	'binary'		=> [ undef, "b", "r",  'Allow binary characters in quoted fields, including line feeds, carriage returns and NULL bytes' ],
	'always_quote'		=> [ undef, "b", "w",  'All defined fields will be quoted even if they need not to' ],
	'quote_space'           => [ undef, "b", "w",  'Quote fields containing spaces (default)' ],
	'quote_null'		=> [ undef, "b", "w",  'NULL bytes in a field would be escaped (default)' ],
	'quote_binary'          => [ undef, "b", "w",  'Quote fields containing "unsafe" bytes >= 0x7f (default)' ],
	'verbatim'		=> [ undef, "b", "r",  'Treat newline (NL) and carriage return (CR) as ordinary binary characters' ],
	'underline'		=> [ undef, "b", "r",  'Print dashes before and after the headers and data' ],
	'field-separator'	=> 'separator'
);

my(%textDesc);

sub textDescInit {

	commonDescInit \%textWords, \%textDesc, @textDesc;

	#Debug '$textDesc{"sep_char"}',        $textDesc{"sep_char"};
	#Debug '$textDesc{"field-separator"}', $textDesc{"field-separator"};
}

sub textCheckOption {

	my($subword,$desc,$must) = @_;
	
	%textDesc or textDescInit;

	return  commonCheckOption \%textDesc, \%textWords, $subword, $desc, $must;
}

sub textOptionHelp {

	%textDesc or textDescInit;
	
	commonOptionHelp \@textHelp, \%textHelp;
}

sub textFileOpen {

	my($filename,$alias,@options) = @_;

	%textDesc or textDescInit;
	
	my(@textOpts,@fileOpts);
	commonFileOpenOptions  \%textDesc, \@textOpts, \@fileOpts, @options;
	
	my($fh)   = fileOpen( "$filename", $alias, @fileOpts );
	
	Trace '$fh', $fh, '@textops', @textOpts if $trace;
	
	return [ $fh, { @textOpts } ];
}

sub textFilePrint {

	my($th) = shift;
	return filePrint $th->[0], map { ref($_)?@$_:$_ } @_;
}

sub textFilePrintf {

	my($th,$format) = ( shift, shift );
	my($fh,$opts,$prebuiltFormat,$originalFormat) = @$th;
	
	if (ref($format)) {
	
	  if ( defined($originalFormat) && $originalFormat == $format ) {

	    $format = $prebuiltFormat;
   	    #Debug "Used prebuilt format $format";
	  } else {
	  
  	    $th->[3] = $format;

	    my($sep) = $opts->{"separator"}; $sep = " " unless defined $sep;
	    my($bnd) = $sep =~ /^\s+$/ ? "" : $sep;
	    
	    $format = $bnd . join($sep,@$format) . "$bnd\n"; 
	    
	    $th->[2] = $format;
	    
	    Trace "Build new format $format" if $trace;
	  }
	}
	
	return filePrintf $th->[0], $format, map { ref($_)?@$_:$_ } @_;
}

sub textFileClose {

	my($th) = shift;
	return fileClose $th->[0];
}

#                  0       1               2                3                  4               5                  6                  7
my($csvRecord) = [ "csv",  \&csvFileOpen,  \&csvFileClose,  \&csvFileReadline, \&csvFilePrint,  \&csvFilePrintf,  \&csvCheckOption,  \&csvOptionHelp ];
my($txtRecord) = [ "text", \&textFileOpen, \&textFileClose, \&fileReadline,    \&textFilePrint, \&textFilePrintf, \&textCheckOption, \&textOptionHelp ];

my(@typeRecords) = ( $csvRecord, $txtRecord );

sub getFileType {

    my($type,$parentdesc) = @_;
    ref($type) and return $type;
    foreach my $s ( split /[^a-zA-Z_]/, $type ) {
	foreach my $t ( @typeRecords ) {
	    $t->[0] eq $s and return [ $t ];
	}
    }
    
    my($allowed) = "'" . join("', '",map{$_->[0]}@typeRecords[0..$#typeRecords-1]) . "'" . ( @typeRecords>2 ? "," : "" ). " and '$typeRecords[$#typeRecords][0]'";
    showUsage "Missing or unsupported file type specification in " . ( $parentdesc ? "--$parentdesc value " : "" ) . "'$type' - only $allowed are allowed";
}
	
sub ioOpen {

	my($filetype,$filename,$alias,@options) = @_;
	my($type) = getFileType($filetype);
	
	return [ $type->[0], $filename && scalar(&{$type->[0][1]}( "$filename", $alias, @options )) ];
}

sub ioType {

	my($ih) = @_;
	return $ih->[0][0];
}

sub ioReadline {

        my($ih,$buffer) = @_;
        
	return &{$ih->[0][3]}($ih->[1],$buffer||\$_); 
}

sub ioClose {

        my($ih,$buffer) = @_;
        
	return &{$ih->[0][2]}($ih->[1]); 
}

sub ioCheckOption {

	my($ih,$subword,$desc,$must) = @_;
	return &{$ih->[0][6]}($subword,$desc||"suboption",$must);
}

sub ioOptionHelp {

	my($ih) = @_;
	return &{$ih->[0][7]}();
}

sub ioOptionValue {

	my($ih,$option) = @_;
	return $ih->[1][1]{$option};
}

sub ioPrint {

        my($ih) = shift;
        
	return &{$ih->[0][4]}($ih->[1],@_); 
}

sub ioPrintf {

        my($ih) = shift;
        
	#Debug @_;

	return &{$ih->[0][5]}($ih->[1],@_); 
}

sub empty {

	my($value) = @_;
	return !defined($value) || $value eq "";
}

sub suboptionBooleanValue {

	my($val) = @_;
	return empty($val) ? 1 : $val =~ /^y(es?)?$|^t(r(ue?)?)?$/i || $val eq "1" ? 1 : $val =~ /^no?|^f(a(l(se?)?)?)?$/i || $val eq "0" ? 0 : undef;
}

sub showOptionUsage {

	my($lefttext,$parentdesc,$kind,$option,$value,$rightext,$useperl) = @_;
	
	showUsage $lefttext, $parentdesc&&"--$parentdesc", $kind, ( $parentdesc ? "suboption '$option'" : "--$option option" ), "value '$value'",  
		  $rightext, $useperl&&", or equivalent Perl expression";
}

sub suboptionValue {

	my($option,$value,$optData,$topts,$parentdesc) = @_;
	
	my($key,$fmt,$iop,$shortText,$longText) = $optData ? @{$optData} : (); 
	my($parsedValue);
	
	if ( $fmt eq "s" || $fmt eq "c" ) {
	
	    $parsedValue = empty($value) ? undef : length($value)<=1 ? $value : eval { $value };
    	    Trace $option, $value, $fmt, $parsedValue if $trace;
	}
	
	if ( $fmt eq "b" ) {
	
	    $parsedValue = suboptionBooleanValue $value;
	    Trace $option, $value, $parsedValue if $trace;
	    defined($parsedValue) or $parsedValue = suboptionBooleanValue eval { $value };
	    Trace $option, $value, $parsedValue if $trace;

	    defined($parsedValue) or 
		showOptionUsage "Invalid", $parentdesc, "boolean", $option, $value, "- use nothing, yes|true|1, no|false|0", 1;
	
	} elsif ( $fmt eq "c" ) {
	
	    empty($parsedValue) || length($parsedValue) == 1 or 
		showOptionUsage "Too many characters in", $parentdesc, "character", $option, $parsedValue, "- use nothing, exactly one character", 1;
		
	} elsif ( $fmt eq "s" ) { ## only /r/n /r /n in real life
	
	    ;
	}
	    
	if ( !empty($parsedValue) ) {
	    $topts->{$key} = $parsedValue;
	} else {
	    delete $topts->{$key};
	}
}
	
sub showSuboptionsErrorHolder {

	my($suboptions,$sublist,$erc) = @_;
	
	$suboptions =~ /^(.*)(\Q$erc\E)(\Q$sublist\E)$/ or return $suboptions;
	
	return "$1<$2>$3";
}

sub showSuboptionUsage {

	my($delim1,$delim2,$parentdesc,$suboptions,$sublist,$erc,$msga) = @_;
	
	showUsage $msga . " in --$parentdesc '".showSuboptionsErrorHolder($suboptions,$sublist,$erc)."' (" . 
	  ( $erc ? "possibly missing suboption name before '$erc' and/or a delimiter, " : "" ) . 
	  "assuming delimiters '$delim1' and '$delim2')"; 
}
			  
sub suboptionParse {

	my($suboptions,$genoptions,$type,$parentdesc) = @_;
	
	$type   = getFileType $suboptions, $parentdesc unless defined($type);
	my($ih) = ref($type) ? $type : inputOpen($type);
	
	my($lopts,$topts) = ( {}, {} );
		
	foreach my $genkey ( keys %$genoptions ) {
	
    	    my($value) = $genoptions->{$genkey};
	    my($subfull,$optData,$all) = ioCheckOption $ih, $genkey, "--$genkey option", 1;
	    
	    suboptionValue $genkey, $value, $optData, $topts, "";
	}
	
	my($delim1) = $suboptions =~ /^[a-zA-Z_0-9]+(.)/ ? $1 : ":";
	my($delim2) = "=";
	
	my(@subopt) = split $delim1, $suboptions;
	
	for ( my $i = 1; $i<@subopt; ++$i ) {
	    my($subfullx,$optDatax,$allx) = ioCheckOption $ih, $subopt[$i], "", -1;
	    !defined($optDatax) or next;
	    
	    $delim2 = $subopt[$i] =~ /^[a-zA-Z_0-9]+(.)/ ? $1 : "=";
	    last;
	}
	
	Trace '$delim1', $delim1, '$delim2', $delim2 if $trace;
	
	my($sublist) = $suboptions;
	while ( $sublist ) {
	
	    $sublist =~ s/^([a-zA-Z_]*)((\Q$delim1\E|\Q$delim2\E)|$|(.))//;
	    my($sub,$dlm,$erc)         = ( $1, $3, $4 );   
	    
	    if ( $sub && $sub eq $ih->[0][0] ) {
	    
		( $dlm && $dlm eq $delim1 ) || ( !$dlm && !$erc ) and next;
		$erc = $dlm unless $erc;
	    }
	    
	    my($subfull,$optData,$all) = $sub ? ioCheckOption( $ih, $sub, "--$parentdesc suboption", 1 ) : ();
	    
    	    #Trace '$subfull', $subfull, '$optData', $optData if $trace;

	    !$erc or do {
	    	showSuboptionUsage $delim1, $delim2, $parentdesc, $suboptions, $sublist, $erc,
		   "Unexpected character '$erc'"; 
	    };
	    
	    $sub or do {
	    	showSuboptionUsage $delim1, $delim2, $parentdesc, $suboptions, $sublist, "",   
		   "Missing suboption name or extra character '$dlm'";
	    };
	    	    
    	    my($value);

	    if ( $dlm && $dlm eq $delim2 && $sublist ) { 
	    
	      my($dlmb);
	      $sublist =~ s/^(.*?)((\Q$delim1\E|\Q$delim2\E)|$)//;
	      ($value,$dlmb) = ( $1, $3 );  
	    	    
	      !$dlmb || $dlmb eq $delim1 or do {
		    showSuboptionUsage $delim1, $delim2, $parentdesc, $suboptions, $sublist, $dlmb,
			"Unexpected delimiter '$dlmb'"; 
	      };
	    }
	    
       	    Trace '$subfull', $subfull, '$value', $value, '$dlm', $dlm, '$optData', $optData if $trace;

	    suboptionValue $subfull, $value, $optData, $topts, $parentdesc;
	}
	
	Debug $topts if $debug;
	
	return $topts;
}

1;
