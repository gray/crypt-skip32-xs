use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME          => 'Crypt::Skip32::XS',
    AUTHOR        => 'gray <gray@cpan.org>',
    LICENSE       => 'perl',
    VERSION_FROM  => 'lib/Crypt/Skip32/XS.pm',
    ABSTRACT_FROM => 'lib/Crypt/Skip32/XS.pm',
    PREREQ_PM     => {
        'Test::More' => 0,
    },
    dist          => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean         => { FILES => 'Crypt-Skip32-XS-*' },
);
