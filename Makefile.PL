use 5.006;
use strict;
use warnings FATAL => 'all';
use inc::Module::Install;

name     'netgang';
abstract 'netgang provides high availability for heterogeneous network interfaces';
version  '1.1.1';
all_from 'lib/netgang.pm';
author   q{"Alexander Murashkin" <"AlexanderMurashkin@msn.com">};
license  'gpl';

perl_version 5.006;

tests_recursive('t');

resources (
   #homepage   => 'http://yourwebsitehere.com',
   #IRC        => 'irc://irc.perl.org/#NetworkGang',
   license    => 'http://www.perlfoundation.org/artistic_license_2_0',
   #repository => 'git://github.com/"Alexander Murashkin"/NetworkGang.git',
   bugtracker => 'http://rt.cpan.org/NoAuth/Bugs.html?Dist=NetworkGang',
);

configure_requires (
   'Module::Install'            => 0,
   'Module::Install::Any'       => 0,
);

build_requires (
   'Test::More'                 => 0,
);


requires (
   'Net::Netmask'               => 1.9015,
   'Try::Tiny'                  => 0.18,
   'Exception::Class'           => 1.37,
   'Text::CSV'                  => 1.30,
);

recommends (

	'Log::Log4perl'                                => 1.42,
	'Log::Log4perl::Appender::Screen'              => 0,
	'Log::Log4perl::Appender::ScreenColoredLevels' => 0,
	'Log::Log4perl::Appender::File'                => 0,
	'Log::Log4perl::Appender::Journald'            => 0,
	'Log::Dispatch::Syslog'                        => 0,
	'Systemd::Daemon'                              => 0.06,
	'Proc::Daemon'                                 => 0.19,	
);

no_index 		directory => 'examples';
install_any     'sbin' => 'sbin', 'share' => 'share/netgang'; 

install_as_cpan;
auto_install;
WriteAll;
