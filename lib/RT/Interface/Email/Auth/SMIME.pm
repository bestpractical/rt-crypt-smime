package RT::Interface::Email::Auth::SMIME;

use warnings;
use strict;

use RT::Crypt::SMIME;
use String::ShellQuote 'shell_quote';

use File::Temp qw/ tempfile /;

=head1 NAME

RT::Interface::Email::Auth::SMIME

=head1 DESCRIPTION

=head2 GetCurrentUser

Returns a CurrentUser object.  Also performs all the commands.

=cut

sub GetCurrentUser {
    my %args = (
        Message       => undef,
        RawMessageRef => undef,
        CurrentUser   => undef,
        AuthLevel     => undef,
        Action        => undef,
        Ticket        => undef,
        Queue         => undef,
        @_
    );


    my $msg = $args{'Message'};
    my $msgref = $args{'RawMessageRef'};
    $RT::Logger->debug('dealing... '.$msg->head->get('Content-type'));

    $RT::Logger->debug( "mime type: " .$msg->head->mime_type );
    if ($msg->head->mime_type =~ /pkcs7-mime/i) {
        $msg->head->set('X-RT-Privacy', 'SMIME');
        my $addr = $args{Action} eq 'correspond'
            ? $args{Queue}->CorrespondAddress || $RT::CorrespondAddress
            : $args{Queue}->CommentAddress    || $RT::CommentAddress
        ;

        decrypt($msg, $msgref, $addr);
    }
    else {
	$msg->head->set('X-RT-Incoming-Encryption', 'Not encrypted')
	    unless $msg->head->get('X-RT-Incoming-Encryption');
    }
    return ($args{'CurrentUser'}, $args{'AuthLevel'});

}


sub decrypt {
    my $msg    = shift;
    my $msgref = shift;
    my $addr   = shift;

    if ( $msg->is_multipart ) {
        $msg->head->set('X-RT-Incoming-Encryption', 'Failed');
        $RT::Logger->crit('S/MIME entity is mutipart');
        return;
    }

    my ($buf, $err);
    {
        local $ENV{SMIME_PASS} = $RT::SMIMEPasswords->{$addr};
        local $SIG{CHLD} = 'DEFAULT';
        RT::Crypt::SMIME::safe_run3(
            shell_quote(
                $RT::OpenSSLPath,
                qw(smime -decrypt -passin env:SMIME_PASS),
                -recip => $RT::SMIMEKeys.'/'.$addr.'.pem',
            ),
            $msgref,
            \$buf,
            \$err
        );
    }
    $RT::Logger->debug( "openssl stderr: " . $err ) if length $err;
    $RT::Logger->debug("decrypted.... ($buf)");

    # XXX: verify sender signature in detach and nodetach mode.

    my $rtparser = _extract_msg_from_buf(\$buf);
    my $decrypted = $rtparser->Entity;

    if ($decrypted->head->mime_type =~ /pkcs7-mime/i) {
	$RT::Logger->debug('nodetach mode signature found');
	$buf = ''; $err = '';
        RT::Crypt::SMIME::safe_run3(
            shell_quote(
                $RT::OpenSSLPath,
                qw(smime -verify -noverify)
            ),
            \$decrypted->as_string,
            \$buf,
            \$err
        );

	$RT::Logger->debug( "openssl stderr: " . $err ) if length $err;
        $rtparser = _extract_msg_from_buf(\$buf);
	$decrypted = $rtparser->Entity;
    }

    $rtparser->{'AttachmentDirs'} = ();
    $msg->head->set('X-RT-Incoming-Encryption', 'Success');
    $msg->make_multipart('mixed');
    $msg->parts([]);
    $msg->add_part( $decrypted );
    $msg->make_singlepart;
}

sub _extract_msg_from_buf {
    my $buf = shift;
    my $rtparser = RT::EmailParser->new();
    my $parser   = MIME::Parser->new();
    $rtparser->_SetupMIMEParser($parser);
    $parser->output_to_core(0);
    unless ( $rtparser->{'entity'} = $parser->parse_data($$buf) ) {
        $RT::Logger->crit(
            "Couldn't parse MIME stream and extract the submessages");

        # Try again, this time without extracting nested messages
        $parser->extract_nested_messages(0);
        unless ( $rtparser->{'entity'} = $parser->parse_data($$buf) ) {
            $RT::Logger->crit("couldn't parse MIME stream");
            return (undef);
        }
    }
    $rtparser->_PostProcessNewEntity;
    return $rtparser;
}

1;
