#!/usr/bin/perl
use strict;
use Test::More;
eval 'use RT::Test; 1'
    or plan skip_all => 'requires 3.7 to run tests.';

plan tests => 47;
use File::Temp;
use IPC::Run3 'run3';
use String::ShellQuote 'shell_quote';
use RT::Tickets;
use FindBin;
use Cwd 'abs_path';

RT->Config->Set( LogToScreen => 'debug' );
RT->Config->Set( LogToSyslog => 'debug' );
RT->Config->Set( 'OpenSSLPath', '/usr/bin/openssl' );
RT->Config->Set( 'SMIMEKeys', abs_path('testkeys') );
RT->Config->Set( 'SMIMEPasswords', {'sender@example.com' => '123456'} );
RT->Config->Set( 'MailPlugins' => 'Auth::MailFrom', 'Auth::SMIME' );

RT::Handle->InsertData('etc/initialdata');

my ($url, $m) = RT::Test->started_ok;
# configure key for General queue
$m->get( $url."?user=root;pass=password" );
$m->content_like(qr/Logout/, 'we did log in');
$m->get( $url.'/Admin/Queues/');
$m->follow_link_ok( {text => 'General'} );
$m->submit_form( form_number => 3,
		 fields      => { CorrespondAddress => 'sender@example.com' } );

my $mail = RT::Test->open_mailgate_ok($url);
print $mail <<EOF;
From: root\@localhost
To: rt\@$RT::rtname
Subject: This is a test of new ticket creation as root

Blah!
Foob!
EOF
RT::Test->close_mailgate_ok($mail);

{
    my $tick = get_latest_ticket_ok();
    is( $tick->Subject,
        'This is a test of new ticket creation as root',
        "Created the ticket"
    );
    my $txn = $tick->Transactions->First;
    like(
        $txn->Attachments->First->Headers,
        qr/^X-RT-Incoming-Encryption: Not encrypted/m,
        'recorded incoming mail that is not encrypted'
    );
    like( $txn->Attachments->First->Content, qr'Blah');
}

# test for encrypted mail
my $buf = '';

run3(
    shell_quote(
        qw(openssl smime -encrypt  -des3),
        -from    => 'root@localhost',
        -to      => 'rt@' . $RT::rtname,
        -subject => "Encrypted message for queue",
        'testkeys/sender@example.com.crt'
    ),
    \"Subject: test\n\norzzzzzz",
    \$buf,
    \*STDERR
);

my $mail = RT::Test->open_mailgate_ok($url);
print $mail $buf;
RT::Test->close_mailgate_ok($mail);

{
    my $tick = get_latest_ticket_ok();
    is( $tick->Subject, 'Encrypted message for queue',
        "Created the ticket"
    );

    my $txn = $tick->Transactions->First;
    my $attach = $txn->Attachments->First;
    is( $attach->GetHeader('X-RT-Incoming-Encryption'),
        'Success',
        'recorded incoming mail that is encrypted'
    );
    like( $attach->Content, qr'orz');
}

{
    open my $fh, $FindBin::Bin.'/../t/data/simple-txt-enc.eml';
    ok(open($mail, "|$RT::BinPath/rt-mailgate --url $url --queue general --action correspond"), "Opened the mailgate - $!");
    print $mail do { local $/; <$fh>};
    close $mail;

    my $tickets = RT::Tickets->new($RT::SystemUser);
    $tickets->OrderBy( FIELD => 'id', ORDER => 'DESC' );
    $tickets->Limit( FIELD => 'id', OPERATOR => '>', VALUE => '0' );
    my $tick = $tickets->First;
    ok( UNIVERSAL::isa( $tick, 'RT::Ticket' ) );
    ok( $tick->Id, "found ticket " . $tick->Id );
    is( $tick->Subject, 'test', 'Created the ticket' );

    my $txn = $tick->Transactions->First;
    my $attach = $txn->Attachments->First;
    is( $attach->GetHeader('X-RT-Incoming-Encryption'),
        'Success',
        'recorded incoming mail that is encrypted'
    );
    ok( $attach->GetHeader('User-Agent'), 'header is there');
    like( $attach->Content, qr'test');
}

{
    open my $fh, $FindBin::Bin.'/../t/data/with-text-attachment.eml';
    ok(open($mail, "|$RT::BinPath/rt-mailgate --url $url --queue general --action correspond"), "Opened the mailgate - $!");
    print $mail do { local $/; <$fh>};
    close $mail;

    my $tickets = RT::Tickets->new($RT::SystemUser);
    $tickets->OrderBy( FIELD => 'id', ORDER => 'DESC' );
    $tickets->Limit( FIELD => 'id', OPERATOR => '>', VALUE => '0' );
    my $tick = $tickets->First;
    ok( UNIVERSAL::isa( $tick, 'RT::Ticket' ) );
    ok( $tick->Id, "found ticket " . $tick->Id );
    is( $tick->Subject, 'test', 'Created the ticket' );
    my $txn = $tick->Transactions->First;
    my @attachments = @{ $txn->Attachments->ItemsArrayRef };
    is( @attachments, 3, '3 attachments: top and two parts' );

    is( $attachments[0]->GetHeader('X-RT-Incoming-Encryption'),
        'Success',
        'recorded incoming mail that is encrypted'
    );
    ok( $attachments[0]->GetHeader('User-Agent'), 'header is there' );
    like( $attachments[1]->Content, qr'test' );
    like( $attachments[2]->Content, qr'text attachment' );
    is( $attachments[2]->Filename, 'attachment.txt' );
}

{
    open my $fh, $FindBin::Bin.'/../t/data/with-bin-attachment.eml';
    ok(open($mail, "|$RT::BinPath/rt-mailgate --url $url --queue general --action correspond"), "Opened the mailgate - $!");
    print $mail do { local $/; <$fh>};
    close $mail;

    my $tickets = RT::Tickets->new($RT::SystemUser);
    $tickets->OrderBy( FIELD => 'id', ORDER => 'DESC' );
    $tickets->Limit( FIELD => 'id', OPERATOR => '>', VALUE => '0' );
    my $tick = $tickets->First;
    ok( UNIVERSAL::isa( $tick, 'RT::Ticket' ) );
    ok( $tick->Id, "found ticket " . $tick->Id );
    is( $tick->Subject, 'test', 'Created the ticket' );
    my $txn = $tick->Transactions->First;
    my @attachments = @{ $txn->Attachments->ItemsArrayRef };
    is( @attachments, 3, '3 attachments: top and two parts' );

    is( $attachments[0]->GetHeader('X-RT-Incoming-Encryption'),
        'Success',
        'recorded incoming mail that is encrypted'
    );
    ok( $attachments[0]->GetHeader('User-Agent'), 'header is there');
    like( $attachments[1]->Content, qr'test');
    is( $attachments[2]->Filename, 'attachment.bin' );
}

{
    $buf = '';

    run3(
        join(
            ' ',
            shell_quote(
                $RT::OpenSSLPath,
                qw( smime -sign -nodetach -passin pass:123456),
                -signer => 'testkeys/recipient.crt',
                -inkey  => 'testkeys/recipient.key'
            ),
            '|',
            shell_quote(
                qw(openssl smime -encrypt  -des3),
                -from    => 'root@localhost',
                -to      => 'rt@' . $RT::rtname,
                -subject => "Encrypted and signed message for queue",
                'testkeys/sender@example.com.crt'
            )),
            \"Subject: test\n\norzzzzzz",
            \$buf,
            \*STDERR
    );

    ok( open(
            $mail,
            "|$RT::BinPath/rt-mailgate --url $url --queue general --action correspond"
        ),
        "Opened the mailgate - $!"
    );
    print $mail $buf;
    close $mail;
    my $tickets = RT::Tickets->new($RT::SystemUser);
    $tickets->OrderBy( FIELD => 'id', ORDER => 'DESC' );
    $tickets->Limit( FIELD => 'id', OPERATOR => '>', VALUE => '0' );
    my $tick = $tickets->First();
    ok( UNIVERSAL::isa( $tick, 'RT::Ticket' ) );
    ok( $tick->Id, "found ticket " . $tick->Id );
    is( $tick->Subject, 'Encrypted and signed message for queue',
        "Created the ticket"
    );

    my $txn = $tick->Transactions->First;
    my $attach = $txn->Attachments->First;
    is( $attach->GetHeader('X-RT-Incoming-Encryption'),
        'Success',
        'recorded incoming mail that is encrypted'
    );
    like( $attach->Content, qr'orzzzz');
}

sub get_latest_ticket_ok {
    my $tickets = RT::Tickets->new($RT::SystemUser);
    $tickets->OrderBy( FIELD => 'id', ORDER => 'DESC' );
    $tickets->Limit( FIELD => 'id', OPERATOR => '>', VALUE => '0' );
    my $tick = $tickets->First();
    ok( $tick->Id, "found ticket " . $tick->Id );
    return $tick;
}
