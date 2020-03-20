#!/usr/bin/perl -w


# Makes a request to the Alexa Top Sites
# to get a list of top sites in a particular country

use  strict;

# If you don't have all the modules below, you can get them from CPAN
#
# perl -MCPAN -e 'install URI::Escape'
# perl -MCPAN -e 'install XML::XPath'
# etc...

use Digest::SHA qw(hmac_sha256_base64), 'sha256_hex','hmac_sha256','hmac_sha256_hex';
use File::Basename;
use URI::Escape;
use LWP::UserAgent;

use XML::XPath;
use XML::XPath::XMLParser;

my $service_endpoint = "ats.amazonaws.com";
my $service_host = "ats.us-west-1.amazonaws.com";
my $action = "TopSites";
my $service_port = 443;
my $service_uri = "/api";
my $service_region = "us-west-1";
my $service_name = "AlexaTopSites";
my $timestamp = generate_timestamp();

my $access_key_id;
my $secret_access_key;
my $country_code;

if ($#ARGV < 1) {
    print STDERR "Usage: " . basename($0) .
        " ACCESS_KEY_ID SECRET_ACCESS_KEY [COUNTRY_CODE]\n";
    exit(-1);
}
else {
    $access_key_id = $ARGV[0];
    $secret_access_key = $ARGV[1];
    $country_code =  ($#ARGV > 1) ? $ARGV[2] : "";
}

my $start = 1;
my $count = 10; # Max value is 100
my ($request_url, $authorization_header) = compose_url($start, $count);

print "Making request to:\n$request_url\n\n";

my $user_agent = LWP::UserAgent->new;
$user_agent->timeout(3);

my $request = HTTP::Request->new('GET', $request_url);
$request->header( 'Accept' => 'application/xml' );
$request->header( 'Content-Type' => 'application/xml' );
$request->header( 'x-amz-date' => $timestamp );
$request->header( 'Authorization' => $authorization_header );
my $response = $user_agent->request($request);

# If valid response, get the contents of the URL,
#  otherwise print error and return empty string.

my $link = "";
if ($response->is_success) {
  print "Sites:\n\n";

  my $output = $response->content;

  # print $output;

  my $xp = XML::XPath->new(xml => $output);

  my @site_nodes = $xp->findnodes('/aws:TopSitesResponse/aws:Response/aws:TopSitesResult/aws:Alexa/aws:TopSites/aws:Country/aws:Sites/aws:Site/aws:DataUrl');
  foreach my $node (@site_nodes) {
      my $value = $node->findvalue('.');
      print "$value\n";
  }
} else {
    print STDERR "Error connecting to $request_url. HTTP Status code: ". $response->code . "\nResponse: \n" . $response->content;
}

sub signing_key {
    my ($kSecret,$service,$region,$date) = @_;
    my $kDate    = hmac_sha256($date,'AWS4'.$kSecret);
    my $kRegion  = hmac_sha256($region,$kDate);
    my $kService = hmac_sha256($service,$kRegion);
    my $kSigning = hmac_sha256('aws4_request',$kService);
    return $kSigning;
}

sub calculate_signature {
    my ($kSecret,$service,$region,$date,$string_to_sign) = @_;
    print "SERVICE: " . $service . "\n";
    my $kSigning = signing_key($kSecret,$service,$region,$date);
    return hmac_sha256_hex($string_to_sign,$kSigning);
}

# Returns the AWS URL to get the site list for the specified country
sub compose_url {
    my ($site) = @_;
    my $uri = {
        'Action'           => $action,
        'ResponseGroup'    => 'Country',
        'CountryCode'      => $country_code,
        'Count'            => $count,
        'Start'            => $start
    };
    my $headers = {
      "host"        => $service_host,
      "x-amz-date"  => $timestamp
    };

    my @hdrs_arr = ();
    my @hdrl_arr = ();
    foreach my $key (sort keys %$headers) {
        push(@hdrs_arr, escape($key) . ':' . escape($headers->{$key}));
        push(@hdrl_arr, escape($key));
    }
    my $hdr_str = join("\n", @hdrs_arr) . "\n";
    my $hdr_lst = join(';', @hdrl_arr);

    my @uri_arr = ();
    #sort hash and uri escape
    foreach my $key (sort keys %$uri) {
        push(@uri_arr, escape($key) . '=' . escape($uri->{$key}));
    }

    my $uri_str = join('&', @uri_arr);
    my $payload_hash = sha256_hex("");
    my $canonical_request = "GET" . "\n" . $service_uri . "\n" . $uri_str . "\n" . $hdr_str . "\n" . $hdr_lst . "\n" . $payload_hash;
    my $algorithm = "AWS4-HMAC-SHA256";
    my $credential_scope = substr($timestamp, 0, 8) . "/" . $service_region . "/" . $service_name . "/" . "aws4_request";
    my $string_to_sign = $algorithm . "\n" .  $timestamp . "\n" .  $credential_scope . "\n" . sha256_hex($canonical_request);
    my $signature =  calculate_signature($secret_access_key,$service_name,$service_region,substr($timestamp, 0, 8),$string_to_sign);
    my $authorization_header = $algorithm . " " . "Credential=" . $access_key_id . "/" . $credential_scope . ", " .  "SignedHeaders=" . $hdr_lst . ", " . "Signature=" . $signature;

    return ('https://' . $service_endpoint . $service_uri . '?' . $uri_str, $authorization_header);
}

# Calculate current TimeStamp
sub generate_timestamp {
    return sprintf("%04d%02d%02dT%02d%02d%02dZ",
                   sub { ($_[5]+1900,
                          $_[4]+1,
                          $_[3],
                          $_[2],
                          $_[1],
                          $_[0])
                   }->(gmtime(time)));
}


# URI escape only the characters that should be escaped, according to RFC 3986
sub escape {
    my ($str) = @_;
    return uri_escape_utf8($str,'^A-Za-z0-9\-_.~');
}

# The digest is the signature
sub digest {
    my ($query) = @_;
    my $digest = hmac_sha256_base64 ($query, $secret_access_key);

    # Digest::MMM modules do not pad their base64 output, so we do
    # it ourselves to keep the service happy.
    return $digest . "=";
}
