package Kernel::System::Auth::OAuth2AuthSync;

use strict;
use warnings;

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::Log',
    'Kernel::System::User',
    'Kernel::System::Group',
);

sub new {
    my ( $Type, %Param ) = @_;

    my $Self = {};
    bless( $Self, $Type );

    return $Self;
}

sub Auth {
    my ( $Self, %Param ) = @_;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
    my $UserObject   = $Kernel::OM->Get('Kernel::System::User');
    my $GroupObject  = $Kernel::OM->Get('Kernel::System::Group');
    my $LogObject    = $Kernel::OM->Get('Kernel::System::Log');

    my $UserLogin =
           $ENV{REMOTE_USER}
        || $ENV{HTTP_X_REMOTE_EMAIL}
        || $ENV{HTTP_X_AUTH_REQUEST_EMAIL}
        || '';

    return if !$UserLogin;

    my %Protected = map { $_ => 1 }
        @{ $ConfigObject->Get('OAuth2AuthSync::ProtectedUsers') || [] };

    return ( $UserLogin, 1 )
        if $Protected{$UserLogin};

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

    my $UserID = $UserObject->UserLookup(
        UserLogin => $UserLogin,
    );

    if (!$UserID) {

        $UserID = $UserObject->UserAdd(
            UserFirstname => $FirstName || 'OAuth2',
            UserLastname  => $LastName  || 'User',
            UserLogin     => $UserLogin,
            UserEmail     => $Email,
            ValidID       => 1,
            ChangeUserID  => 1,
        );

        $LogObject->Log(
            Priority => 'notice',
            Message  => "OAuth2AuthSync created user <$UserLogin>",
        );
    }

    if ($UserID) {

        $UserObject->UserUpdate(
            UserID        => $UserID,
            UserFirstname => $FirstName,
            UserLastname  => $LastName,
            UserEmail     => $Email,
            ChangeUserID  => 1,
        );
    }

    my $GroupsHeader =
           $ENV{HTTP_X_REMOTE_GROUPS}
        || $ENV{HTTP_X_AUTH_REQUEST_GROUPS}
        || '';

    my %GroupMapping =
        %{ $ConfigObject->Get('OAuth2AuthSync::GroupMapping') || {} };

    if ($UserID && $GroupsHeader) {

        my @EntraGroups = split /\s*,\s*/, $GroupsHeader;

        GROUP:
        for my $EntraGroup (@EntraGroups) {

            my $ZnunyGroup = $GroupMapping{$EntraGroup};

            next GROUP if !$ZnunyGroup;

            my $GroupID = $GroupObject->GroupLookup(
                Group => $ZnunyGroup,
            );

            next GROUP if !$GroupID;

            for my $Permission (qw(ro rw)) {

                $GroupObject->PermissionGroupUserAdd(
                    UID           => $UserID,
                    GID           => $GroupID,
                    PermissionKey => $Permission,
                    UserID        => 1,
                );
            }
        }
    }

    return (
        $UserLogin,
        1,
    );
}

1;