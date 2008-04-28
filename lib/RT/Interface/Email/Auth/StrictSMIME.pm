package RT::Interface::Email::Auth::StrictSMIME;

use warnings;
use strict;

use RT::Crypt::SMIME ();
use RT::Action::SendEmail ();
use RT::Interface::Email qw(ParseSenderAddressFromHead);

=head1 NAME

RT::Interface::Email::Auth::StrictSMIME - strict SMIME protection

=head1 DESCRIPTION

If message is not encrypted with SMIME standard then report error to
sender and doesn't create or update ticket.

=head1 CONFIGURATION

Add this filter after standard RT's one and before any other.
Configuration should be something like the following:

  @MailPlugins = (qw(Auth::MailFrom Auth::StrictSMIME Auth::SMIME));

As well you need template 'NotEncryptedMessage', this template is used
to notify senders that their message was not recorded. When the template
is called an object of the current ticket may be not available so you
have to avoid any code in the template that doesn't check this fact. Use
conditions C<if ( $TicketObj && $TicketObj->id ) {...}>. In general
situation next template should work just fine:

  Subject: [ERROR] Couldn't process a message

  Hi, message you sent was not processed as it was not encrypted with
  SMIME encryption. Please, resubmit your request using encryption
  facility.

=head1 CAVEATS

This plugin should work normal with RT 3.6.3, but this version of RT
has a little bit broken logic, so you may see undesirable side effects
and probably wrong results. To fix issues we provide a patch you can
find in patches dir within the tarball, changes in the patch are in the
RT's repository and would be available with RT 3.6.4.

=head1 METHODS

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

    return ($args{'CurrentUser'}, $args{'AuthLevel'})
        if $args{'Action'} && $args{'Action'} ne 'comment'
                           && $args{'Action'} ne 'correspond';

    return ($args{'CurrentUser'}, $args{'AuthLevel'})
        if IsEncrypted( $args{'Message'} );

    $RT::Logger->info( 'Message is not encrypted, sending error' );
    
    my $template = RT::Template->new( $RT::SystemUser );
    $template->LoadGlobalTemplate('NotEncryptedMessage');
    unless ( $template->id ) {
        $RT::Logger->crit( "Couldn't load template 'NotEncryptedMessage'");
        return ($args{'CurrentUser'}, $args{'AuthLevel'});
    }
    $template->Parse( TicketObj => $args{'Ticket'} );

    my $error_msg = $template->MIMEObj;
    my $sender = (ParseSenderAddressFromHead( $args{'Message'}->head ))[0];
    $error_msg->head->set( To => $sender );

    local $RT::Crypt::SMIME::NO_ENCRYPTION = 1;
    RT::Interface::Email->can('SendEmail')
        ? RT::Interface::Email::SendEmail( Entity => $error_msg )
        : RT::Action::SendEmail->OutputMIMEObject( $error_msg );

    return ($args{'CurrentUser'}, -2);
}

sub IsEncrypted {
    my $msg = shift;

    # RFC3851 Ch. 3.9. Identifying an S/MIME Message
    my $fname = $msg->head->recommended_filename;

    # RFC3851 defines 'application/pkcs7-mime' only, however some clients
    # use 'application/x-pkcs7-mime' type, so we use more generic regexp 
    my $type = lc $msg->head->mime_type;
    if ( $type =~ /pkcs7-mime/ ) {
        $RT::Logger->debug('smime message, detected by mime type');
        unless ( $fname ) {
            $RT::Logger->debug('[passed] no file name');
            return 1;
        }
        $RT::Logger->debug('file name is '. $fname);
        if ( lc substr($fname, -3) eq 'p7m' ) {
            $RT::Logger->debug('[passed] file name has extension p7m');
            return 1;
        }
        $RT::Logger->debug('[denied] file name has incorrect name');
        return 0;
    }
    elsif ( $type eq 'application/octet-stream' ) {
        unless ( $fname ) {
            $RT::Logger->debug('[denied] octet-stream type, but not a named file');
            return 0;
        } elsif ( lc substr($fname, -3) eq 'p7m' ) {
            $RT::Logger->debug('[passed] detected by octet-stream type and file ext');
            return 1;
        } else {
            $RT::Logger->debug("[denied] octet-stream type, but file's ext is not *.p7m");
            return 0;
        }
    }
    else {
        $RT::Logger->debug("[denied] '$type' is not correct");
        return 0;
    }
    return 0;
}

1;
