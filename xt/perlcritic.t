use strict;
use Test::More;

eval { require Test::Perl::Critic };
if ($@) {
    plan skip_all => "Test::Perl::Critic is not installed.";
}
Test::Perl::Critic->import(-profile => "xt/perlcriticrc");

all_critic_ok(qw( ex lib t xt ));
