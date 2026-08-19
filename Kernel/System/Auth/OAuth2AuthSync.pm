package Kernel::System::AuthSync::OAuth2AuthSync;

use strict;
use warnings;

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::User',
    'Kernel::System::Group',
    'Kernel::System::Log',
);

sub new {
    my ( $Type, %Param ) = @_;

    my $Self = {};
    bless( $Self, $Type );

    return $Self;
}

sub _ReadHeader {
    my ( $Self, $Headers ) = @_;

    HEADER:
    for my $Header ( @{$Headers} ) {

        next HEADER if !$ENV{$Header};

        return $ENV{$Header};
    }

    return;
}

sub Sync {
    my ( $Self, %Param ) = @_;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
    my $UserObject   = $Kernel::OM->Get('Kernel::System::User');
    my $GroupObject  = $Kernel::OM->Get('Kernel::System::Group');
    my $LogObject    = $Kernel::OM->Get('Kernel::System::Log');

    my $UserLogin = $Param{User};

    my @LoginHeaders =
        @{ $ConfigObject->Get('OAuth2AuthSync::Headers::Login') || [] };

    if ( !$UserLogin ) {
        $UserLogin = $Self->_ReadHeader( \@LoginHeaders );
    }

    return if !$UserLogin;

    my %Protected = map { $_ => 1 }
        @{ $ConfigObject->Get('OAuth2AuthSync::ProtectedUsers') || [] };

    return 1 if $Protected{$UserLogin};

    my $Email = $Self->_ReadHeader(
        $ConfigObject->Get('OAuth2AuthSync::Headers::Email') || []
    );

    my $FirstName = $Self->_ReadHeader(
        $ConfigObject->Get('OAuth2AuthSync::Headers::GivenName') || []
    );

    my $LastName = $Self->_ReadHeader(
        $ConfigObject->Get('OAuth2AuthSync::Headers::Surname') || []
    );

    my $DisplayName = $Self->_ReadHeader(
        $ConfigObject->Get('OAuth2AuthSync::Headers::DisplayName') || []
    );

    if ( !$FirstName && $DisplayName ) {

        if ( $DisplayName =~ /^(.+?)\s+(.+)$/ ) {
            $FirstName = $1;
            $LastName  = $2;
        }
    }

    $Email ||= $UserLogin;

    my $UserID = $UserObject->UserLookup(
        UserLogin => $UserLogin,
    );

    if (!$UserID) {

        $UserID = $UserObject->UserAdd(
            UserLogin     => $UserLogin,
            UserFirstname => $FirstName || 'OAuth2',
            UserLastname  => $LastName  || 'User',
            UserEmail     => $Email,
            ValidID       => 1,
            ChangeUserID  => 1,
        );

        $LogObject->Log(
            Priority => 'notice',
            Message  => "OAuth2AuthSync created user $UserLogin",
        );
    }

    return if !$UserID;

    $UserObject->UserUpdate(
        UserID        => $UserID,
        UserLogin     => $UserLogin,
        UserFirstname => $FirstName,
        UserLastname  => $LastName,
        UserEmail     => $Email,
        ValidID       => 1,
        ChangeUserID  => 1,
    );

    my $GroupsHeader = $Self->_ReadHeader(
        $ConfigObject->Get('OAuth2AuthSync::Headers::Groups') || []
    );

    return 1 if !$GroupsHeader;

    my %Mapping =
        %{ $ConfigObject->Get('OAuth2AuthSync::GroupMapping') || {} };

    my @Groups = split /\s*,\s*/, $GroupsHeader;

    GROUP:
    for my $EntraGroup (@Groups) {

        my $ZnunyGroup = $Mapping{$EntraGroup};

        next GROUP if !$ZnunyGroup;

        my $GroupID = $GroupObject->GroupLookup(
            Group => $ZnunyGroup,
        );

        next GROUP if !$GroupID;

        $GroupObject->PermissionGroupUserAdd(
            UID           => $UserID,
            GID           => $GroupID,
            PermissionKey => 'rw',
            UserID        => 1,
        );
    }

    return 1;
}

1;