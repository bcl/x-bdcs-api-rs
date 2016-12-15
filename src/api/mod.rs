//! BDCS API Server handlers
//!
// Copyright (C) 2016
// Red Hat, Inc.  All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//!
//! # Overview
//!
//! The API server uses the [Nickel.rs](http://nickel.rs) web framework to handle requests.  The
//! handler functions are called by Nickel as part of its Middleware plugin system.
//!
//! The [bdcs::db](bdcs/db/index.html) module is used for the database operations. None of the
//! handlers should be executing SQL on the database directly.
//!
//! Requests are via HTTP for now, eventually it will be https only.
//!
//! # Methods
//!
//! * `GET` - is used to retrieve results from the server. No changes are made to the state of the
//!   server using a `GET` request.
//! * `POST` - is used to initiate a change or an action on the server. eg. write a Recipe, start a
//!   compose, etc.
//!
//! All other HTTP methods are unused at this time.
//!
//! # HTTP Status Codes
//!
//! Status codes will be used along with JSON responses to indicate the success or failure of
//! requests.
//!
//! * `2xx` - Success, JSON response depends on the resource being accessed.
//! * `4xx` - Request failure, additional details in the JSON error response.
//! * `5xx` - Server errors, additional details in the JSON error response.
//!
//! # Versioning
//!
//! API access is always versioned, and old versions will remain accessible unless explicitly
//! deprecated for 1 version release cycle.
//!
//! The base path of the URLs are `/api/v0/` with the REST resource root starting after that.
//!
//! # REST
//!
//! URLs are used to describe the resources being accessed. Generally trying to follow the advice
//! [found here](http://blog.mwaysolutions.com/2014/06/05/10-best-practices-for-better-restful-api/)
//! except for point 6, HATEOAS.
//!
//! * Use plural nouns for resources, and HTTP Methods as the verbs.
//! * GET does not alter the state of the server
//! * Use sub-resources for relations (eg. TODO Add an example)
//! * Use query parameters to filter, sort, and paginate results. eg. `/api/v0/recipes/list?limit=50&offset=42`
//!
//! # Responses
//!
//! All responses will be JSON objects. Responses to GET requests will have the response included
//! under a key set to the resource root. eg. `GET /api/v0/recipes/list` will return the list as
//! `{"recipes":[{"name":value, ...}, ...]}`
//!
//! Responses may also include extra metadata in other keys. eg. limit, offset, and total for
//! pagination results.
//!
//! ## Error Responses
//!
//! In addition to the HTTP Error codes, extra information will be included in a JSON response object with
//! `{"id": "internal error id", "msg": "Human readable message, suitable for passing to users"}`
//!
//! # Authentication
//!
//! This is still TBD.
//!
//! ## Authorization: Bearer tokens
//!
//! ## Basic Auth tokens
//!
pub mod v0;


use base64::decode;
use config::BDCSConfig;
use crypto::sha2::Sha256;
use hyper::header::{self, Authorization, Basic, Bearer};
use jwt::{Header, Registered, Token};
use nickel::{Request, Response, MiddlewareResult};
use nickel::status::StatusCode;

// TODO Should come from a config file
static AUTH_SECRET: &'static str = "Earn_more_sessions_by_sleeving";

/// Enable CORS support
///
/// # Arguments
///
/// * `_req` - Unused Request structure
/// * `res` - Response to me modified
///
/// # Returns
///
/// * A `MiddlewareResult`
///
/// See [the Mozilla page](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS)
/// for more details about CORS.
///
/// This modifies the headers so that API calls can be executed from javascript that is not running
/// on the same host as the API server.
///
/// # TODO
///
/// * Add the Access-Control-Allow-Credentials header -- it needs an actual domain for Origin in
///   order to work.
///
pub fn enable_cors<'mw>(_req: &mut Request<BDCSConfig>, mut res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
    // Set appropriate headers
    res.set(header::AccessControlAllowOrigin::Any);
    res.set(header::AccessControlAllowHeaders(vec![
        // Hyper uses the `unicase::Unicase` type to ensure comparisons are done
        // case-insensitively. Here, we use `into()` to convert to one from a `&str`
        // so that we don't have to import the type ourselves.
        "Origin".into(),
        "X-Requested-With".into(),
        "Content-Type".into(),
        "Accept".into(),
    ]));

    // Pass control to the next middleware
    res.next_middleware()
}


/// JWT Authentication support
///
/// # Arguments
///
/// * `_req` - Unused Request structure
/// * `res` - Response to me modified
///
/// # Returns
///
/// * A `MiddlewareResult` or Forbidden
///
/// # Panics
///
/// * It will panic if no authorization header is found.
///
/// The authentication is not checked for OPTIONS requests, nor for /users/login requests.
///
pub fn jwt_auth<'mw>(req: &mut Request<BDCSConfig>, mut res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
    if req.origin.method.to_string() == "OPTIONS".to_string() {
        // The middleware should not be used for OPTIONS, so continue
        res.next_middleware()
    } else if req.origin.uri.to_string().ends_with("/users/login") {
        // We do not want to apply the middleware to the login route
        res.next_middleware()
    } else {
        let jwt_token: String;

        // Get the full Authorization header from the incoming request headers
        if let Some(header) = req.origin.headers.get::<Authorization<Bearer>>() {
            let jwt = header::HeaderFormatter(header).to_string();
            jwt_token = jwt[7..].to_string();
        } else {
            if let Some(header) = req.origin.headers.get::<Authorization<Basic>>() {
                let jwt = header::HeaderFormatter(header).to_string();
                // The Basic auth has : and possibly a password. Split it and ignore password
                let jwt_bytes = decode(&jwt[6..]).unwrap();
                jwt_token = String::from_utf8(jwt_bytes)
                    .unwrap()
                    .rsplitn(2, ":")
                    .last()
                    .unwrap()
                    .to_string();
            } else {
                // TODO Return a proper error to the client
                panic!("No authorization header found")
            }
        }

        // Parse the token
        println!("{:?}", jwt_token);
        let token = Token::<Header, Registered>::parse(&jwt_token).unwrap();

        // Get the secret key as bytes
        let secret = AUTH_SECRET.as_bytes();

        // Verify the token
        if token.verify(&secret, Sha256::new()) {
            // TODO Add user details to req someplace? Verify it against the db? Check expiration?
            res.next_middleware()
        } else {
            res.error(StatusCode::Forbidden, "Access denied")
        }
    }
}
