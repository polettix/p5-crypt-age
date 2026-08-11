package Crypt::Age::Simple;
use v5.24;
use warnings;
use experimental qw< signatures >;
use English;
our $VERSION = '0.002';

use Crypt::Age;
use Crypt::Age::Header;
use Crypt::Age::Keys;
use Crypt::Age::Primitives;
use Crypt::Age::Stanza;
use Crypt::AuthEnc::ChaCha20Poly1305;
use Crypt::KeyDerivation qw< argon2_pbkdf scrypt_pbkdf >;
use Crypt::PRNG qw(random_bytes);
use Ouch qw< :trytiny_var >;
use Time::HiRes qw< time >;

use constant {
   DEFAULT_N_LOG_2    => 18,
   DEFAULT_KDF => '$agex-argon2id',

   SCRYPT_SALT_PREFIX => 'age-encryption.org/v1/scrypt',
   VERSION_LINE       => "age-encryption.org/v1",

   CHUNK_SIZE      => 64 * 1024,  # 64 KiB
   NONCE_SIZE      => 16,  # different from Crypt::Age::Primitives
   SALT_SIZE       => 16,
   TAG_SIZE        => 16,
   X25519_KEY_SIZE => 32,

   KDF_DEFAULTS_FOR => {
      (
         map { $_ => { t => 30, m => 65536, p => 1, } }
            qw< agex-argon2i agex-argon2d agex-argon2id >,
      ),
      'agex-scrypt' => { ln => 19, r => 8, p => 1 },
   },

   READ_ATTEMPTS  => 3,
};

use Exporter qw< import >;
our %EXPORT_TAGS = (
   scrypt => [ qw<
      age_scrypt_decrypt
      age_scrypt_decrypt_file
      age_scrypt_decrypt_fh
      age_scrypt_encrypt
      age_scrypt_encrypt_file
      age_scrypt_encrypt_fh
   > ],
   x25519 => [ qw<
      age_x25519_decrypt
      age_x25519_decrypt_file
      age_x25519_decrypt_fh
      age_x25519_encrypt
      age_x25519_encrypt_file
      age_x25519_encrypt_fh
      age_x25519_extract_public_key
      age_x25519_extract_secret_key
      age_x25519_generate_keypair
   > ],
   kdf  => [ qw< password_to_key > ],
);
our @EXPORT_OK = map { $_->@* } values(%EXPORT_TAGS);
$EXPORT_TAGS{all} = [ @EXPORT_OK ];

# initialize with default value
our $WorkFactorLog2 = DEFAULT_N_LOG_2;


########################################################################
#
# age scrypt decryption
#
########################################################################

sub age_scrypt_decrypt ($password, $input) {
   return _fh_wrap(age_scrypt_decrypt_fh => \$input, undef, $password);
}

sub age_scrypt_decrypt_file ($password, $input, $output) {
   return _fh_wrap(age_scrypt_decrypt_fh => $input, $output, $password);
}

sub age_scrypt_decrypt_fh ($password, $ifh, $ofh) {
   _to_raw($ifh, $ofh);

   my $header = Crypt::Age::Header->can('parse_from_fh')
      ? Crypt::Age::Header->parse_from_fh($ifh)
      : _age_header_parse_from_fh($ifh);

   my @stanzas = $header->stanzas->@*;
   ouch 'header not for scrypt' if @stanzas != 1;
   ouch 'header stanza not of scrypt type' if $stanzas[0]->type ne 'scrypt';

   my $file_key = _age_scrypt_unwrap_file_key($stanzas[0], $password)
      or ouch 400, 'undefined file key... wrong password?';
   $header->verify_mac($file_key)
      or ouch 400, 'MAC verification failed... wrong password?';

   my $nonce = _age_read_nonce($ifh);
   my $payload_key
      = Crypt::Age::Primitives->derive_payload_key($file_key, $nonce);

   return _age_decrypt_payload_fh($payload_key, $ifh, $ofh);
}


########################################################################
#
# age scrypt encryption
#
########################################################################

sub age_scrypt_encrypt ($password, $input) {
   return _fh_wrap(age_scrypt_encrypt_fh => \$input, undef, $password);
}

sub age_scrypt_encrypt_file ($password, $input, $output) {
   return _fh_wrap(age_scrypt_encrypt_fh => $input, $output, $password);
}

sub age_scrypt_encrypt_fh ($password, $ifh, $ofh) {
   _to_raw($ifh, $ofh);

   my $file_key = Crypt::Age::Primitives->generate_file_key;

   my $header = _age_scrypt_header($file_key, $password);
   print {$ofh} $header, "\x{0a}";

   my $nonce = Crypt::Age::Primitives->generate_payload_nonce;
   print {$ofh} $nonce;

   my $payload_key
      = Crypt::Age::Primitives->derive_payload_key($file_key, $nonce);
   _age_encrypt_payload_fh($payload_key, $ifh, $ofh);
}


########################################################################
#
# age X25519 decryption
#
########################################################################

sub age_x25519_decrypt ($id, $input) {
   return _fh_wrap(age_x25519_decrypt_fh => \$input, undef, $id);
}

sub age_x25519_decrypt_file ($id, $input, $output) {
   return _fh_wrap(age_x25519_decrypt_fh => $input, $output, $id);
}

sub age_x25519_decrypt_fh ($id, $ifh, $ofh) {
   return Crypt::Age->decrypt_filehandle(
      input => $ifh,
      output => $ofh,
      identities => _as_arrayref($id),
   ) if Crypt::Age->can('decrypt_filehandle');
   return _age_x25519_decrypt_fh($ifh, $ofh, _as_arrayref($id));
}


########################################################################
#
# age X25519 encryption
#
########################################################################

sub age_x25519_encrypt ($recipients, $input) {
   return _fh_wrap(age_x25519_encrypt_fh => \$input, undef, $recipients);
}

sub age_x25519_encrypt_file ($recipients, $input, $output) {
   return _fh_wrap(age_x25519_encrypt_fh => $input, $output, $recipients);
}

sub age_x25519_encrypt_fh ($recipients, $ifh, $ofh) {
   return Crypt::Age->encrypt_filehandle(
      input => $ifh,
      output => $ofh,
      recipients => _as_arrayref($recipients),
   ) if Crypt::Age->can('encrypt_filehandle');
   return _age_x25519_encrypt_fh($ifh, $ofh, _as_arrayref($recipients));
}


########################################################################
#
# age X25519 key management helpers
#
########################################################################

sub age_x25519_extract_public_key ($text) {
   return _bech32_match($text, 'age');
}

sub age_x25519_extract_secret_key ($text) {
   return _bech32_match($text, 'AGE-SECRET-KEY-');
}

sub age_x25519_generate_keypair {
   return Crypt::Age->generate_keypair();
}

########################################################################
#
# key derivation from a password
#
########################################################################

sub password_to_key ($password, $config = undef, $pepper = undef) {
   $config = _normalize_config($config);
   $pepper = '' unless defined($pepper);

   my $id = $config->{id}
      or ouch 400, 'no identifier in kdf configuration';
   my $cb = _cb_for(_agep2k_ => $id)
      or ouch 404, "unsupported identifier <$id> in kdf configuration";

   my $start = time();
   my $secret_raw = $cb->($password, $config, $pepper);
   $config->{elapsed} = time() - $start;
   my $secret = Crypt::Age::Keys->encode_secret_key($secret_raw);
   my $public = Crypt::Age::Keys->public_key_from_secret($secret);
   $config->{public} = $public;

   return {
      config => $config,
      phc    => _kdfconfig_to_phc($config),
      public => $public,
      secret => $secret,
   };
}


########################################################################
#
# private functions
#
########################################################################

sub _phc_params ($href, @keys) {
   return join ',',
      map { join('=', $_, $href->{$_}) }
      grep { defined($href->{$_}) }
      @keys;
}

sub __phc_from_argon2 ($id, $config) {
   my $v = join('=', v => $config->{version} // 19);
   my $ps = _phc_params($config->{params}, qw< m t p >);
   my @args = ($id, $v, $ps, $config->{salt});
   push @args, $config->{public} if defined($config->{public});
   return join('$', '', @args);
}
sub _phc_from_argon2i  { return __phc_from_argon2('agex-argon2i'  => @_) }
sub _phc_from_argon2d  { return __phc_from_argon2('agex-argon2d'  => @_) }
sub _phc_from_argon2id { return __phc_from_argon2('agex-argon2id' => @_) }

sub _phc_from_scrypt ($config) {
   my $ps = _phc_params($config->{params}, qw< ln r p >);
   my @args = ($config->{id} => $ps, $config->{salt});
   push @args, $config->{public} if defined($config->{public});
   return join('$', '', @args);
}

sub _cb_for ($prefix, $id) {
   my ($subid) = $id =~ m{\A agex- (\S+) \z}mxs
      or ouch 400, "invalid id<$id>";
   return __PACKAGE__->can($prefix . $subid);
}

sub _kdfconfig_to_phc ($config) {
   my $id = $config->{id}
      or ouch 400, 'no identifier in kdf configuration';
   my $cb = _cb_for(_phc_from_ => $id)
      or ouch 404, "unsupported identifier <$id> in kdf configuration";
   return $cb->($config);
}

sub _phc_to_hash ($phc) {
   ouch 400, 'undefined PHC' unless defined $phc;

   my %retval;

   # validate identifier
   my ($empty, $id, @other) = split m{\$}mxs, $phc;
   ouch 400, 'invalid PHC' unless $empty eq '';
   ouch 400, 'invalid id in PHC' unless $id =~ m{\A[-a-z0-9]{1,32}\z}mxs;
   $retval{id} = $id;

   if (@other && $other[0] =~ m{\Av=([0-9]+)\z}mxs) { # version
      $retval{version} = $1;
      shift(@other);
   }

   $retval{params} = {
      map {
         my ($k, $v) = split m{=}mxs, $_;
         ouch 400, "forbidden key <v> in params" if $k eq 'v';
         ouch 400, "invalid key <$k> in params"
            if $k !~ m{\A[-a-z0-9]{1,32}\z}mxs;
         ouch 400, "invalid value <$v> in params"
            if $v !~ m{\A[-a-zA-Z0-9/+.]*\z}mxs;
         ($k, $v);
      } split m{,}mxs, shift(@other)
   } if @other && $other[0] =~ m{=}mxs;

   if (@other) {
      $other[0] =~ m{\A[-a-zA-Z0-9/+.]+\z}mxs
         or ouch 400, "invalid salt <$other[0]>";
      $retval{salt} = shift(@other);
   }

   $retval{payload} = shift(@other) if @other;

   ouch 400, "invalid PHC, too many parts" if @other > 0;
   return %retval if wantarray;
   return \%retval;
}

sub _normalize_config ($config) {
   $config //= DEFAULT_KDF;
   $config = _phc_to_hash($config) unless ref($config);
   $config = { $config->%* };

   # check that the identifier is supported
   my $id = $config->{id};
   my $default_for = KDF_DEFAULTS_FOR->{$id}
      or ouch 400, "unknown key derivation function <$id>";

   my $params = $config->{params} //= {};
   $params->{$_} //= $default_for->{$_} for keys($default_for->%*);

   if (defined($config->{salt})) {
      $config->{saltraw}
         = Crypt::Age::Stanza::decode_base64_no_padding($config->{salt});
   }
   else {
      my $salt = $config->{saltraw} = random_bytes(SALT_SIZE);
      $config->{salt}
         = Crypt::Age::Stanza::encode_base64_no_padding($salt);
   }

   return $config;
}

sub __agep2k_argon2 ($type, $password, $config, $pepper) {
   return argon2_pbkdf($type, $password, $config->{saltraw},
      $config->{params}->@{qw< t m p >}, X25519_KEY_SIZE, $pepper, '');
}
sub _agep2k_argon2i  { return __agep2k_argon2(argon2i  => @_) }
sub _agep2k_argon2d  { return __agep2k_argon2(argon2d  => @_) }
sub _agep2k_argon2id { return __agep2k_argon2(argon2id => @_) }

sub _agep2k_scrypt ($password, $config, $pepper) {
   my $N = 2 ** $config->{params}{ln};
   return scrypt_pbkdf($password, $config->{saltraw},
      $N, $config->{params}->@{qw< r p >}, X25519_KEY_SIZE);
   # yes, we disregard the pepper because scrypt has none
}


# implementation rehashed from Crypt::Age and a proposal for evolution
sub _age_read_nonce ($ifh) {
    my $nonce = _age_primitives_paranoid_read($ifh, NONCE_SIZE);
    ouch 400, 'end of file reached before getting nonce'
      if length($nonce) != NONCE_SIZE;
    return $nonce;
}

sub _age_x25519_decrypt_fh ($ifh, $ofh, $identities) {
    _to_raw($ifh, $ofh);

    ouch 400, "identities must be an array ref"
      if ref($identities) ne 'ARRAY';
    ouch 400, "at least one identity required" unless $identities->@*;

    # Parse header
    my $header = _age_header_parse_from_fh($ifh);

    # Unwrap file key using identities
    my $file_key = $header->unwrap_file_key($identities);

    # Extract nonce (first 16 bytes after header) and encrypted payload
    my $nonce = _age_read_nonce($ifh);

    # Derive payload key using nonce
    my $payload_key
      = Crypt::Age::Primitives->derive_payload_key($file_key, $nonce);

    return _age_decrypt_payload_fh($payload_key, $ifh, $ofh);
}

sub _age_x25519_encrypt_fh ($ifh, $ofh, $recipients) {
    _to_raw($ifh, $ofh);

    ouch 400, "recipients must be an array ref"
      if ref($recipients) ne 'ARRAY';
    ouch 400, "at least one recipient required" unless $recipients->@*;

    # Generate random file key
    my $file_key = Crypt::Age::Primitives->generate_file_key;

    # Create header with wrapped file key for each recipient
    my $header = Crypt::Age::Header->create($file_key, $recipients);
    print {$ofh} $header->to_string;

    # Generate payload nonce and derive payload key
    my $nonce = Crypt::Age::Primitives->generate_payload_nonce;
    print {$ofh} $nonce;

    my $payload_key
      = Crypt::Age::Primitives->derive_payload_key($file_key, $nonce);

    return _age_encrypt_payload_fh($payload_key, $ifh, $ofh);
}

sub _age_decrypt_payload_fh ($payload_key, $ifh, $ofh) {
    my $max_encrypted_chunk = CHUNK_SIZE + TAG_SIZE;
    my $counter = 0;
    my $is_final = 0;
    while (! $is_final) {
        # Each encrypted chunk is plaintext + 16 byte tag
        my $ct = _age_primitives_paranoid_read($ifh, $max_encrypted_chunk);
        my $tag = substr($ct, -TAG_SIZE, TAG_SIZE, '');

        $is_final = eof($ifh);
        my $nonce = _age_primitives_make_nonce($counter, $is_final);
        my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($payload_key, $nonce);

        my $plaintext = $ae->decrypt_add($ct);
        ouch 400, "Payload authentication failed at chunk $counter"
            unless $ae->decrypt_done($tag);

        print {$ofh} $plaintext;

        $counter++;
    }

    return 1;
}

sub _age_encrypt_payload_fh ($payload_key, $ifh, $ofh) {
    my $counter = 0;
    my $is_final = 0;
    while (! $is_final) {
        my $chunk = _age_primitives_paranoid_read($ifh, CHUNK_SIZE);
        $is_final = eof($ifh);

        my $nonce = _age_primitives_make_nonce($counter, $is_final);
        my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($payload_key, $nonce);

        my $ciphertext = $ae->encrypt_add($chunk);
        my $tag = $ae->encrypt_done;

        print {$ofh} $ciphertext, $tag;

        $counter++;
    }

    return 1;
}

sub _age_header_parse_from_fh ($fh) {

    # make sure to read the whole thing in the correct way
    local $/ = "\x{0a}";

    # $header will eventually contain the whole header, for MAC validation.
    # We start from the first line.
    my $bytes = <$fh>;

    # Check version
    chomp(my $version_line = $bytes); # remove \x{0a}
    ouch 400, "Invalid age version: $version_line"
      if $version_line ne VERSION_LINE;

    # read the rest of the header
    my (@stanzas, $mac);
    my $n = 0;
    while (<$fh>) {
        if (my ($mac64) = m{\A ---\x{20} (\S{43}) \x{0a} \z}mxs) {
            $bytes .= '---';
            $mac = Crypt::Age::Stanza::decode_base64_no_padding($mac64);
            last;
        }
        ++$n;
        my ($ta) = m{\A ->\x{20} (\S+ (?:\x{20}\S+)*) \x{0a} \z}mxs
            or ouch 400, "Invalid age stanza #$n start line: <$_>";

        $bytes .= $_;

        # Read stanza's body lines
        my $body_b64 = '';
        my $body_completed = 0;
        while (<$fh>) {
            $bytes .= $_;
            chomp;
            my $len = length($_);
            ouch 400, "Invalid age stanza #$n body" if $len > 64;
            $body_b64 .= $_;
            if ($len < 64) {
                $body_completed = 1;
                last;
            }
        }
        # "The body MUST end with a line shorter than 64 characters, which
        #  MAY be empty."
        ouch 400, "Invalid age stanza #$n body" unless $body_completed;

        my ($type, @args) = split m{\x{20}}mxs, $ta;
        my $body = Crypt::Age::Stanza::decode_base64_no_padding($body_b64);

        my $stanza_class = 'Crypt::Age::Stanza';
        if ($type eq 'X25519') {
            $stanza_class = 'Crypt::Age::Stanza::X25519';
        }

        push @stanzas, $stanza_class->new(
            type => $type,
            args => \@args,
            body => $body,
        );
    }
    ouch 400, "Invalid age file, no valid header MAC line"
      unless length($mac // '');

    return Crypt::Age::Header->new(
        stanzas => \@stanzas,
        bytes   => $bytes,
        mac     => $mac,
    );
}

sub _age_primitives_paranoid_read ($fh, $length) {
    my $retval = '';
    my $attempts = READ_ATTEMPTS;
    while ($length > 0 && $attempts > 0) {
        my $buffer = '';
        my $n_read = read($fh, $buffer, $length);
        ouch 400, "read(): $!" if ! defined($n_read);
        if ($n_read == 0) {
            last if eof($fh); # no more data, we're good
            --$attempts;
            next;
        }

        # reset attempts after successful read of *some* data
        $attempts = READ_ATTEMPTS;
        $retval .= $buffer;
        $length -= $n_read;
    }
    return $retval if $attempts > 0;
    ouch 400, "could not get requested data up to the end";
}

# copied from Crypt::Age::Primitives 0.002 because it's a private method
# there...
sub _age_primitives_make_nonce ($counter, $is_final) {

    # 11 bytes counter (big-endian) + 1 byte final flag
    my $nonce = pack('x3 N N', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
    # Actually, the nonce is: 11-byte big-endian counter || 1-byte last-block flag
    # Let's be more precise:
    $nonce = "\x00" x 3;  # First 3 bytes zero
    $nonce .= pack('N', ($counter >> 32) & 0xFFFFFFFF);  # Next 4 bytes
    $nonce .= pack('N', $counter & 0xFFFFFFFF);          # Next 4 bytes
    $nonce .= pack('C', $is_final ? 1 : 0);              # Last byte: final flag

    return $nonce;
}

sub _to_raw ($ifh, $ofh) {
    binmode($ifh, ':raw')
      or ouch 500, "cannot binmode input filehandle: $OS_ERROR";
    binmode($ofh, ':raw')
      or ouch 500, "cannot binmode output filehandle: $OS_ERROR";
    return;
}

sub _as_arrayref ($x) { ref($x) eq 'ARRAY' ? $x : [ $x ] }

sub _fh_wrap ($sub_name, $input, $output, @args) {
   my $buffer = '';
   my $wants_output = 0;
   if (! defined($output)) {
      $output = \$buffer;
      $wants_output = 1;
   }
   open my $ifh, '<:raw', $input or ouch 500, "open() input string: $!";
   open my $ofh, '>:raw', $output or ouch 500, "open() output string: $!";
   __PACKAGE__->can($sub_name)->(@args, $ifh, $ofh);
   close $ofh;
   close $ifh;
   return $buffer if $wants_output;
   return 1;
}

sub _bech32_match ($text, $prefix) {
   my $alphabet = 
   my ($retval) = $text =~ m{
      \b(
         \Q$prefix\E
         1
         [qpzry9x8gf2tvdw0s3jn54khce6mua7l]+
      )\b
   }imxs;
   return $retval;
}

sub _age_scrypt_wrap_key ($password, $salt, $Nlog2) {
   my $full_salt = SCRYPT_SALT_PREFIX . $salt;
   my $N = 2 ** $Nlog2;
   my $r = 8;
   my $p = 1;
   my $len = 32;
   return scrypt_pbkdf($password, $full_salt, $N, $r, $p, $len);
}

sub _age_base64_multiline ($data) {
   my $data64 = Crypt::Age::Stanza::encode_base64_no_padding($data);
   my @lines;
   push @lines, substr($data64, 0, 64, '') while length($data64) > 64;
   return join("\x{0a}", @lines, $data64);
}

sub _age_scrypt_header ($file_key, $password) {
   my $salt = random_bytes(SALT_SIZE);
   my $Nlog2 = our $WorkFactorLog2;
   my $wrap_key = _age_scrypt_wrap_key($password, $salt, $Nlog2);
   my $body = Crypt::Age::Primitives->wrap_file_key($wrap_key, $file_key);

   # create header
   my $salt64 = Crypt::Age::Stanza::encode_base64_no_padding($salt);
   my $stanza_header = "-> scrypt $salt64 $Nlog2";
   my $stanza_body   = _age_base64_multiline($body);
   my $header
      = join("\x{0a}", VERSION_LINE, $stanza_header, $stanza_body, '---');
   my $mac
      = Crypt::Age::Primitives->compute_header_mac($file_key, $header);
   my $mac64 = Crypt::Age::Stanza::encode_base64_no_padding($mac);
   return join "\x{20}", $header, $mac64;
}

sub _age_scrypt_unwrap_file_key ($stanza, $password) {
   my ($salt64, $Nlog2) = $stanza->args->@*;
   my $salt = Crypt::Age::Stanza::decode_base64_no_padding($salt64);
   my $wrap_key = _age_scrypt_wrap_key($password, $salt, $Nlog2);
   my $body = $stanza->body;
   my $file_key = eval {
      Crypt::Age::Primitives->unwrap_file_key($wrap_key, $body);
   };
   return $file_key;
}

1;
