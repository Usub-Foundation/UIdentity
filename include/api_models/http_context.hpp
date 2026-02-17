#pragma once
#include <string>
#include <unordered_map>
#include <vector>

struct HttpRequest
{
  std::string method;
  std::string path;
  std::unordered_map<std::string, std::string> headers;
  std::string body;
  std::string query;
};

struct HttpResponse
{
  int status = 200;
  std::unordered_map<std::string, std::string> headers;
  std::string body;
};

struct RequestContext
{
  bool authenticated = false;

  // identity-ish (from access token claims)
  std::string sub;                // user id
  std::string preferred_username; // optional
  std::string issuer;             // iss
  std::string client_id;          // azp or client_id-ish

  // authz
  std::vector<std::string> roles;  // realm roles or client roles
  std::vector<std::string> scopes; // parsed "scope" claim if used
};

struct AuthConfig
{
  std::string expected_issuer; // e.g. "https://kc.example.com/realms/my-realm"
  std::string jwks_url;        // expected_issuer + "/protocol/openid-connect/certs"

  // How strict you want to be (tighten later)
  bool require_audience = false;
  std::string expected_audience; // your API audience if configured
  std::string expected_azp;      // your SPA client id, e.g. "spa-client" (useful if aud is messy)

  int clock_skew_seconds = 60;
};

struct AuthResult
{
  bool ok;
  int http_status;   // 200, 401, 403
  std::string error; // short error code
};