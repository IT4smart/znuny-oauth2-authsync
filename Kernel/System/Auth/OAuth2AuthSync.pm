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

sub Sync {
    my ( $Self, %Param ) = @_;

    my $UserLogin = $Param{User};

    return if !$UserLogin;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
    my $UserObject   = $Kernel::OM->Get('Kernel::System::User');
    my $GroupObject  = $Kernel::OM->Get('Kernel::System::Group');
    my $LogObject    = $Kernel::OM->Get('Kernel::System::Log');

    my @ProtectedUsers =
        @{ $ConfigObject->Get('OAuth2AuthSync::ProtectedUsers') || [] };

    my %Protected = map { $_ => 1 } @ProtectedUsers;

    return 1 if $Protected{$UserLogin};

    my $Email =
           $ENV{HTTP_X_REMOTE_EMAIL}
        || $ENV{HTTP_X_AUTH_REQUEST_EMAIL}
        || $UserLogin;

    my $FirstName =
           $ENV{HTTP_X_REMOTE_GIVEN_NAME}
        || $ENV{HTTP_X_AUTH_REQUEST_GIVEN_NAME}
        || '';

    my $LastName =
           $ENV{HTTP_X_REMOTE_FAMILY_NAME}
        || $ENV{HTTP_X_AUTH_REQUEST_FAMILY_NAME}
        || '';

    my $DisplayName =
           $ENV{HTTP_X_REMOTE_NAME}
        || $ENV{HTTP_X_AUTH_REQUEST_NAME}
        || '';

    if ( !$FirstName && $DisplayName =~ /^(.+?)\s+(.+)$/ ) {
        $FirstName = $1;
        $LastName  = $2;
    }

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
            Message  => "OAuth2AuthSync created user <$UserLogin>",
        );

        return if !$UserID;
    }

    $UserObject->UserUpdate(
        UserID        => $UserID,
        UserFirstname => $FirstName,
        UserLastname  => $LastName,
        UserEmail     => $Email,
        ValidID       => 1,
        ChangeUserID  => 1,
    );

    my $GroupsHeader =
           $ENV{HTTP_X_REMOTE_GROUPS}
        || $ENV{HTTP_X_AUTH_REQUEST_GROUPS}
        || $ENV{HTTP_X_FORWARDED_GROUPS}
        || '';

    my %GroupMapping =
        %{ $ConfigObject->Get('OAuth2AuthSync::GroupMapping') || {} };

    return 1 if !$GroupsHeader;

    my @EntraGroups = split /\s*,\s*/, $GroupsHeader;

    my %WantedGroups;

    GROUP:
    for my $EntraGroup (@EntraGroups) {

        my $ZnunyGroup = $GroupMapping{$EntraGroup};

        next GROUP if !$ZnunyGroup;

        my $GroupID = $GroupObject->GroupLookup(
            Group => $ZnunyGroup,
        );

        next GROUP if !$GroupID;

        $WantedGroups{$GroupID} = 1;
    }

    for my $GroupID ( keys %WantedGroups ) {

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