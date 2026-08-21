package Kernel::System::AuthSync::OAuth2AuthSync;

use strict;
use warnings;

use MIME::Base64 qw(decode_base64url);
use JSON qw(decode_json);

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::User',
    'Kernel::System::Group',
    'Kernel::System::Log',
    'Kernel::System::DB',
);

sub new {
    my ( $Type, %Param ) = @_;

    my $Self = {};
    bless( $Self, $Type );

    return $Self;
}

sub _ReadAccessToken {
    my ( $Self ) = @_;

    my $Token = $ENV{HTTP_X_ACCESS_TOKEN};

    return if !$Token;

    my @Parts = split /\./, $Token;

    return if scalar @Parts < 2;

    my $Payload;

    eval {
        $Payload = decode_base64url( $Parts[1] );
    };

    return if !$Payload;

    my $Claims;

    eval {
        $Claims = decode_json($Payload);
    };

    return if !$Claims;

    return $Claims;
}

sub _DetermineLogin {
    my ( $Self, $Claims ) = @_;

    return $ENV{REMOTE_USER}
        if $ENV{REMOTE_USER};

    return $ENV{HTTP_X_REMOTE_EMAIL}
        if $ENV{HTTP_X_REMOTE_EMAIL};

    return $Claims->{preferred_username}
        if $Claims && $Claims->{preferred_username};

    return $Claims->{email}
        if $Claims && $Claims->{email};

    return;
}

sub _GroupExists {
    my ( $Self, %Param ) = @_;

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');

    my $Exists;

    return if !$DBObject->Prepare(
        SQL => '
            SELECT id
            FROM group_user
            WHERE user_id = ?
            AND group_id = ?
            AND permission_key = ?
        ',
        Bind => [
            \$Param{UserID},
            \$Param{GroupID},
            \$Param{PermissionKey},
        ],
    );

    while ( my @Row = $DBObject->FetchrowArray() ) {
        $Exists = $Row[0];
    }

    return $Exists;
}

sub _GroupAdd {
    my ( $Self, %Param ) = @_;

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');

    return if $Self->_GroupExists(
        UserID       => $Param{UserID},
        GroupID      => $Param{GroupID},
        PermissionKey => 'rw',
    );

    return $DBObject->Do(
        SQL => '
            INSERT INTO group_user
            (
                user_id,
                group_id,
                permission_key,
                create_time,
                create_by,
                change_time,
                change_by
            )
            VALUES
            (
                ?, ?, ?,
                current_timestamp,
                1,
                current_timestamp,
                1
            )
        ',
        Bind => [
            \$Param{UserID},
            \$Param{GroupID},
            \'rw',
        ],
    );
}

sub Sync {
    my ( $Self, %Param ) = @_;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
    my $UserObject   = $Kernel::OM->Get('Kernel::System::User');
    my $GroupObject  = $Kernel::OM->Get('Kernel::System::Group');
    my $LogObject    = $Kernel::OM->Get('Kernel::System::Log');

    my $Claims = $Self->_ReadAccessToken();

    my $UserLogin =
           $Param{User}
        || $Self->_DetermineLogin($Claims);

    return 1 if !$UserLogin;

    $LogObject->Log(
        Priority => 'notice',
        Message  => "OAuth2AuthSync: Processing <$UserLogin>",
    );

    my %ProtectedUsers = map { $_ => 1 }
        @{ $ConfigObject->Get('OAuth2AuthSync::ProtectedUsers') || [] };

    if ( $ProtectedUsers{$UserLogin} ) {

        $LogObject->Log(
            Priority => 'notice',
            Message  => "OAuth2AuthSync: Protected user <$UserLogin>",
        );

        return 1;
    }

    my $Email =
           $ENV{HTTP_X_REMOTE_EMAIL}
        || ($Claims && $Claims->{email})
        || $UserLogin;

    my $FirstName =
           $ENV{HTTP_X_REMOTE_GIVEN_NAME}
        || ($Claims && $Claims->{given_name})
        || '';

    my $LastName =
           $ENV{HTTP_X_REMOTE_FAMILY_NAME}
        || ($Claims && $Claims->{family_name})
        || '';

    my $DisplayName =
           $ENV{HTTP_X_REMOTE_NAME}
        || ($Claims && $Claims->{name})
        || '';

    if ( !$FirstName && !$LastName && $DisplayName ) {

        if ( $DisplayName =~ /^(.+?)\s+(.+)$/ ) {
            $FirstName = $1;
            $LastName  = $2;
        }
    }

    my $UserID = $UserObject->UserLookup(
        UserLogin => $UserLogin,
    );

    if (!$UserID) {

        $LogObject->Log(
            Priority => 'notice',
            Message  => "OAuth2AuthSync: Creating user <$UserLogin>",
        );

        $UserID = $UserObject->UserAdd(
            UserLogin     => $UserLogin,
            UserFirstname => $FirstName || 'OAuth2',
            UserLastname  => $LastName  || 'User',
            UserEmail     => $Email,
            ValidID       => 1,
            ChangeUserID        => 1,
        );

        $UserID = $UserObject->UserLookup(
            UserLogin => $UserLogin,
        );

        if (!$UserID) {

            $LogObject->Log(
                Priority => 'error',
                Message  => "OAuth2AuthSync: User creation failed",
            );

            return;
        }
    }

    $UserObject->UserUpdate(
        UserID        => $UserID,
        UserLogin     => $UserLogin,
        UserFirstname => $FirstName,
        UserLastname  => $LastName,
        UserEmail     => $Email,
        ValidID       => 1,
        ChangeUserID  => 1,
    );

    $LogObject->Log(
        Priority => 'notice',
        Message =>
            "OAuth2AuthSync: User synced UserID=$UserID Email=$Email",
    );

    my @EntraGroups;

    if ( $ENV{HTTP_X_REMOTE_GROUPS} ) {

        @EntraGroups =
            split /\s*,\s*/, $ENV{HTTP_X_REMOTE_GROUPS};

        $LogObject->Log(
            Priority => 'notice',
            Message =>
                "OAuth2AuthSync: Header groups="
                . join( ',', @EntraGroups ),
        );
    }
    elsif (
        $Claims
        && $Claims->{groups}
        && ref $Claims->{groups} eq 'ARRAY'
        )
    {

        @EntraGroups = @{ $Claims->{groups} };

        $LogObject->Log(
            Priority => 'notice',
            Message =>
                "OAuth2AuthSync: JWT groups="
                . join( ',', @EntraGroups ),
        );
    }

    my $GroupMapping =
        $ConfigObject->Get('OAuth2AuthSync::GroupMapping') || {};

    GROUP:
    for my $EntraGroup (@EntraGroups) {

        my $Mapped = $GroupMapping->{$EntraGroup};

        next GROUP if !$Mapped;

        my @ZnunyGroups =
            ref $Mapped eq 'ARRAY'
            ? @{$Mapped}
            : ($Mapped);

        for my $ZnunyGroup (@ZnunyGroups) {

            my $GroupID = $GroupObject->GroupLookup(
                Group => $ZnunyGroup,
            );

            if (!$GroupID) {

                $LogObject->Log(
                    Priority => 'error',
                    Message =>
                        "OAuth2AuthSync: Group <$ZnunyGroup> not found",
                );

                next;
            }

            $LogObject->Log(
                Priority => 'notice',
                Message =>
                    "OAuth2AuthSync: Inserting group relation "
                    ."UserID=$UserID GroupID=$GroupID",
            );

            my $Success = $Self->_GroupAdd(
                UserID  => $UserID,
                GroupID => $GroupID,
            );

            $LogObject->Log(
                Priority => 'notice',
                Message =>
                    "OAuth2AuthSync: Added UserID=$UserID "
                  . "to Group=$ZnunyGroup "
                  . "(ID=$GroupID) "
                  . "Result="
                  . ( $Success // 'already-exists' ),
            );
        }
    }

    return 1;
}

1;