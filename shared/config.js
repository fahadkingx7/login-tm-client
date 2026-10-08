globalThis.CS = globalThis.CS || {};
CS.CONFIG = Object.freeze({
  supabaseUrl: "https://thdxsonrjazeoadhidbx.supabase.co",
  supabasePublishableKey: "sb_publishable_Wk6lijFpADVLgxQkUnM2LA_nmkCqEXA",
  supabaseEdgeUrl: "https://thdxsonrjazeoadhidbx.supabase.co/functions/v1/admin-users",
  // Use a small, sequential fallback chain so one public-IP provider outage
  // does not make a healthy proxy look broken. Only the first successful
  // endpoint is used, so normal health checks still make a single request.
  ipCheckUrls: Object.freeze([
    "https://api.ipify.org?format=json",
    "https://checkip.amazonaws.com/",
    "https://ipv4.icanhazip.com/"
  ]),
  version: "6.1.35"
});
