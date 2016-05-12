package SecurityTests;
use FoswikiFnTestCase();
use Foswiki::UI::Attach();
our @ISA = qw( FoswikiFnTestCase );

# use strict;

my $testWeb = 'Main'; #'TemporaryTestWeb'; # name of the test web
my $testTopic = 'WebHome'; #'TestTopic';      # name of a topic
my $session; # Foswiki instance

sub new {
    my $self = shift()->SUPER::new(@_);
    #$self->{test_web} = $testWeb;
    #$self->{test_topic} = $testTopic;
    #$self->{test_user_login} = Foswiki::cfg{AdminUserLogin}
    return $self;
}

sub set_up {
    my $this = shift; # the Test::Unit::TestCase object
    $this->SUPER::set_up();
    $session = undef;
}

sub create_session {
    my $this = shift;
    my $query_opts = shift;
    # Make up a simple query
    my $query = new Unit::Request($query_opts);
    $query->path_info("/$this->{test_web}/$this->{test_topic}");
    $query->action("attach");

    # Create a Foswiki instance
    $session = $this->createNewFoswikiSession( $this->{test_user_login},$query );
    return $session;
}

sub create_web_query {
    my $this, $query_opts = shift;
    
    # Make up a simple query
    my $query = new Unit::Request($query_opts);
    # $query->path_info("/$this->{test_web}/$this->{test_topic}");
    $query->action("attach");
    my $response = new Unit::Response();
    $response->charset("utf8");


    # Create a Foswiki instance
    $session = $this->createNewFoswikiSession( $this->{test_user_login},$query );
    # $session = new Foswiki(undef, $query);

    # and use it to create some test webs
    # Need priveleged user to create root webs with Foswiki::Func.
    Foswiki::Func::createWeb( $this->{test_web} );
}


sub tear_down {
    my $this = shift; # the Test::Unit::TestCase object

    if ($session) {
        # This will erase the test webs
        # $this->removeWebFixture( $session, $testWeb );
        #$this->removeWebFixture( $session, $testUsersWeb );

        # This will destroy the Foswiki instance.  We use eval to suppress errors
        #eval { $session->finish() };
        1;
    }

    # This will automatically restore the state of $Foswiki::cfg
    $this->SUPER::tear_down();
}

sub test_setup {

    # if this test fails, there may be something wrong with the design of 
    # other tests testing real issues.

    my $this = shift;

    $this->create_session({ filename => [ "goober" ] });
    my $query = $this->{request};

    $this->assert_str_equals("attach", $query->action());
    $this->assert_str_equals("filename=goober", $query->queryString());
    $this->assert_str_equals("goober", scalar($query->param('filename')));

    # print $query->url(-query => 1), "\n";

    my($respText, $result, $stdout, $stderr) = $this->captureWithKey(
        attach => sub {
            no strict 'refs';
            Foswiki::UI::Attach::attach( $this->{session} );
            use strict 'refs';
            $Foswiki::engine->finalize( $this->{session}{response},
                                        $this->{session}{request} );
        });

    # print $respText, "\n";

    $this->assert_matches(qr/<input [^>]* value="goober"/, $respText);

}

sub test_attach_filename_xss {

    my $this = shift;

    # send filename="><sCrIpT>alert(66562)</sCrIpT>
    $this->create_session({ filename => [ '"><sCrIpT>alert(66562)</sCrIpT>' ] });
    my $query = $this->{request};

    # print $query->url(-query => 1), "\n";

    my($respText, $result, $stdout, $stderr) = $this->captureWithKey(
        attach => sub {
            no strict 'refs';
            Foswiki::UI::Attach::attach( $this->{session} );
            use strict 'refs';
            $Foswiki::engine->finalize( $this->{session}{response},
                                        $this->{session}{request} );
        });

    print $respText, "\n";

    # our filename got it in in some form...
    $this->assert_matches(qr/sCrIpT/, $respText,
                          "Expected to see harmless trace of filename (sCrIpT)");

    # ...but must not allow pop-up alert
    $this->assert_matches(qr/<sCrIpT>alert\(66562\)<\/sCrIpT>/, $respText,
    #$this->assert_does_not_match(qr/<sCrIpT>alert\(66562\)<\/sCrIpT>/, $respText,
                          "Detected Javascript injection: " .
                          "<sCrIpT>alert\(66562\)<\/sCrIpT>");

}

1;
