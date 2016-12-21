//! BDCS API handlers version 0
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
//!
//! # TODO
//!
//!  * Implement generic gzip handling for all responses.
//!  * Handle Authentication, similar to the [example here.](https://auth0.com/blog/build-an-api-in-rust-with-jwt-authentication-using-nickelrs/)
//!
use config::BDCSConfig;
use flate2::Compression;
use flate2::write::GzEncoder;
use glob::glob;
use hyper::header::{self, qitem};
use nickel::{MediaType, Request, Response, MiddlewareResult, QueryString, JsonBody};
use nickel::status::StatusCode;
use nickel_sqlite::SqliteRequestExtensions;
use rusqlite::Error;
use rustc_serialize::json::{self, ToJson, Json};
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use toml;

// bdcs database functions
use db::{self, get_builds_name, get_build_files, get_projects_name, get_project_kv_project_id, get_builds_project_id,
        get_build_kv_build_id, get_source_id, get_source_kv_source_id, get_groups_name};


/// This is used to hold the details about the availabe output types supported by composer
///
/// This will eventually come from a plugin system instead of being a static list constructed
/// by the handler.
#[derive(RustcEncodable)]
struct ComposeTypes {
    name: String,
    enabled: bool
}

impl ComposeTypes {
    /// Create a new ComposeTypes struct
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the output type. eg. 'iso'
    /// * `enabled` - Whether or not that type is actually enabled.
    ///
    /// # Returns
    ///
    /// * A new [ComposeTypes](struct.ComposeTypes.html) struct
    ///
    fn new<S: Into<String>>(name: S, enabled: bool) -> ComposeTypes {
        ComposeTypes { name: name.into(), enabled: enabled }
    }
}

/// Recipe names
///
/// This is used to easily parse the recipe's TOML, keys that don't exist are ignored,
/// so this only parses the name of each recipe.
///
#[derive(Debug, RustcDecodable, RustcEncodable)]
struct RecipeList {
    name: Option<String>,
}

/// Composer Recipe
///
/// This is used to parse the full recipe's TOML, and to write a JSON representation of
/// the Recipe.
///
#[derive(Debug, RustcDecodable, RustcEncodable)]
struct Recipe {
    name: Option<String>,
    description: Option<String>,
    modules: Option<Vec<Modules>>,
    packages: Option<Vec<Packages>>
}

/// Recipe Modules
///
/// This is used for the Recipe's `modules` section and can be serialized
/// to/from JSON and TOML.
#[derive(Debug, RustcDecodable, RustcEncodable)]
struct Modules {
    name: Option<String>,
    version: Option<String>
}

/// Recipe Packages
///
/// This is used for the Recipe's `packages` section
#[derive(Debug, RustcDecodable, RustcEncodable)]
struct Packages {
    name: Option<String>,
    version: Option<String>
}


/// Project Information
///
/// These are used to represent detailed project information, including
/// all metadata K:V pairs, builds and source info.
#[derive(Debug,RustcEncodable)]
struct ProjectInfo {
    name: String,
    summary: String,
    description: String,
    homepage: Option<String>,
    upstream_vcs: String,
    metadata: Option<HashMap<String, String>>,
    builds: Option<Vec<BuildInfo>>,
}

#[derive(Debug,RustcEncodable)]
struct BuildInfo {
    epoch: i64,
    release: String,
    arch: String,
    build_time: String,
    changelog: String,
    build_config_ref: String,
    build_env_ref: String,
    metadata: Option<HashMap<String, String>>,
    source: Option<SourceInfo>,
}

#[derive(Debug,RustcEncodable)]
struct SourceInfo {
    license: String,
    version: String,
    source_ref: String,
    metadata: Option<HashMap<String, String>>
}

#[derive(Debug,RustcEncodable)]
struct ProjectsResult {
    projects: Option<Vec<ProjectInfo>>,
    offset:   Option<i64>,
    limit:    Option<i64>,
    id:       Option<ErrorId>,
    msg:      Option<String>,
}

// TODO Do something useful with this
#[derive(Debug,RustcEncodable)]
enum ErrorId {
    Basic,
    Complicated
}


/// Test the connection to the API
///
/// # Arguments
///
/// * `_req` - Unused Request structure
/// * `res` - Response to be modified
///
/// # Returns
///
/// * A `MiddlewareResult`
///
/// # Response
///
///  * Sends a string to the client - `API v0 test`
///
/// # TODO
///
/// * Change this to JSON and report the version number?
///
pub fn test_v0<'mw>(_req: &mut Request<BDCSConfig>, res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
   res.send("API v0 test")
}


/// Report that an API path is unimplemented
///
/// # Arguments
///
/// * `_req` - Unused Request structure
/// * `res` - Response to be modified
///
/// # Returns
///
/// * A `MiddlewareResult`
///
/// # Response
///
/// * HTTP Error
///
/// This means that it will be implemented eventually, and is a valid path.
///
/// # TODO
///
/// * Change it to a meaningful error code and JSON response
///
pub fn unimplemented_v0<'mw>(_req: &mut Request<BDCSConfig>, res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
   res.error(StatusCode::ImATeapot, "API Not Yet Implemented.")
}


/// Return the compose types and whether or not they are currently supported
///
/// # Arguments
///
/// * `_req` - Unused Request structure
/// * `res` - Response to be modified
///
/// # Returns
///
/// * A `MiddlewareResult`
///
/// # Response
///
/// * JSON response with 'types' set to a list of {'name':value, 'enabled': true|false} entries.
///
/// # Panics
///
/// * Failure to serialize the response
///
/// # Examples
///
/// ```json
/// {"types":[{"enabled":true,"name":"iso"},{"enabled":false,"name":"disk-image"},{"enabled":false,"name":"fs-image"},{"enabled":false,"name":"ami"},{"enabled":false,"name":"tar"},{"enabled":false,"name":"live-pxe"},{"enabled":false,"name":"live-ostree"},{"enabled":false,"name":"oci"},{"enabled":false,"name":"vagrant"},{"enabled":false,"name":"qcow2"},{"enabled":false,"name":"vmdk"},{"enabled":false,"name":"vhdx"}]}
/// ```
///
pub fn compose_types_v0<'mw>(_req: &mut Request<BDCSConfig>, mut res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
    let mut types = Vec::new();
    types.push(ComposeTypes::new("iso", true));
    types.push(ComposeTypes::new("disk-image", false));
    types.push(ComposeTypes::new("fs-image", false));
    types.push(ComposeTypes::new("ami", false));
    types.push(ComposeTypes::new("tar", false));
    types.push(ComposeTypes::new("live-pxe", false));
    types.push(ComposeTypes::new("live-ostree", false));
    types.push(ComposeTypes::new("oci", false));
    types.push(ComposeTypes::new("vagrant", false));
    types.push(ComposeTypes::new("qcow2", false));
    types.push(ComposeTypes::new("vmdk", false));
    types.push(ComposeTypes::new("vhdx", false));

    let mut response = HashMap::new();
    response.insert("types".to_string(), types);

    res.set(MediaType::Json);
    res.send(json::encode(&response).expect("Failed to serialize"))
}


/// Return detailed information about a list of package names
///
/// # Arguments
///
/// * `req` - Request from client
/// * `res` - Response to be modified
///
/// # Returns
///
/// * A `MiddlewareResult`
///
/// # Request
///
/// * `packages` - comma separated list of package names
///
/// # Response
///
/// * JSON response with 'dnf' set to ...
///
/// # Panics
///
/// * Failure to get a database connection
///
/// # TODO
///
/// * Figure out how to package up all the details and output it as JSON
///
pub fn dnf_info_packages_v0<'mw>(req: &mut Request<BDCSConfig>, res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
    // Get the build details for NM
    let packages = req.param("packages").unwrap_or("").split(",");

    // Why does passing 'foo' match the route and passing: 'foo.1.1'
    // fail?

    let conn = req.db_conn().expect("Failed to get a database connection from the pool.");
    for pkg in packages {
        let result = get_builds_name(&conn, pkg);
        match result {
            Ok(builds) => {
                println!("===> package = {}", pkg);
                for build in builds {
                    println!("{:?}", build);
                    let s = String::from_utf8(build.changelog);
                    println!("Changelog:\n{}", s.unwrap());
                    println!("Files for build:");
                    let file_results = get_build_files(&conn, build.id);
                    match file_results {
                        Ok(files) => {
                            for f in files {
                                println!("{:?}", f);
                            }
                        }
                        Err(err) => println!("Error: {}", err)
                    }
                }
            }
            Err(err) => println!("Error: {}", err)
        }
    }
//    res.set(MediaType::Json);
    res.send("Write This")
}


/// Return detailed information about a list of package names
///
/// # Arguments
///
/// * `req` - Request from the client
/// * `res` - Response to be modified
///
/// # Returns
///
/// * A `MiddlewareResult`
///
/// # Request
///
/// * `offset` - Number of results to skip before returning results. Default is 0.
/// * `limit` - Maximum number of results to return. It may return less. Default is 20.
///
/// # Response
///
/// * JSON response with a list of {'name': value, 'summary': value} entries.
///
/// If the client supports it, the results of this are gzipped before being sent.
///
/// # Panics
///
/// * Failure to get a database connection
/// * Failure to serialize the response
///
/// # Examples
///
/// ```json
/// [{"name":"389-ds-base","summary":"389 Directory Server (base)"},{"name":"ElectricFence","summary":"A debugger which detects memory allocation violations"},{"name":"GConf2","summary":"A process-transparent configuration system"},{"name":"GeoIP","summary":"Library for country/city/organization to IP address or hostname mapping"},{"name":"ImageMagick","summary":"An X application for displaying and manipulating images"},{"name":"LibRaw","summary":"Library for reading RAW files obtained from digital photo cameras"},{"name":"ModemManager","summary":"Mobile broadband modem management service"},{"name":"MySQL-python","summary":"An interface to MySQL"},{"name":"NetworkManager","summary":"Network connection manager and user applications"},{"name":"NetworkManager-libreswan","summary":"NetworkManager VPN plug-in for libreswan"},{"name":"ORBit2","summary":"A high-performance CORBA Object Request Broker"},{"name":"OpenEXR","summary":"OpenEXR runtime libraries"},{"name":"OpenIPMI","summary":"IPMI (Intelligent Platform Management Interface) library and tools"},{"name":"PackageKit","summary":"Package management service"},{"name":"PyGreSQL","summary":"A Python client library for PostgreSQL"},{"name":"PyPAM","summary":"PAM bindings for Python"},{"name":"PyQt4","summary":"Python bindings for Qt4"},{"name":"PyYAML","summary":"YAML parser and emitter for Python"},{"name":"Red_Hat_Enterprise_Linux-Release_Notes-7-as-IN","summary":"Assamese translation of Release_Notes"},{"name":"Red_Hat_Enterprise_Linux-Release_Notes-7-bn-IN","summary":"Bengali translation of Release_Notes"}]
/// ```
///
/// # TODO
///
/// * Change the response to be {'projects': [ ... ]}
///
fn project_result(projs: Vec<db::Projects>, offset: i64, limit: i64) -> Result<ProjectsResult, Error> {
    let mut project_list = Vec::new();
    for p in projs {
        project_list.push(ProjectInfo {
                            name:         p.name,
                            summary:      p.summary,
                            description:  p.description,
                            homepage:     p.homepage,
                            upstream_vcs: p.upstream_vcs,
                            metadata:     None,
                            builds:       None
                        });
    }

    Ok(ProjectsResult {
           projects: Some(project_list),
           offset:   Some(offset),
           limit:    Some(limit),
           id:       None,
           msg:      None
    })
}

fn error_result(err: Error, offset: i64, limit: i64) -> Result<ProjectsResult, Error> {
    Ok(ProjectsResult {
           id:       Some(ErrorId::Basic),
           msg:      Some(format!("Some kind of error: {:?}", err)),
           offset:   Some(offset),
           limit:    Some(limit),
           projects: None
    })
}

pub fn project_list_v0<'mw>(req: &mut Request<BDCSConfig>, mut res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
    let offset: i64;
    let limit: i64;
    {
        let query = req.query();
        offset = query.get("offset").unwrap_or("").parse().unwrap_or(0);
        limit = query.get("limit").unwrap_or("").parse().unwrap_or(20);
    }

    let conn = req.db_conn().expect("Failed to get a database connection from the pool.");
    let result = get_projects_name(&conn, "*", offset, limit)
                    .and_then(|projs| project_result(projs, offset, limit))
                    .or_else(|projs| error_result(projs, offset, limit))
                    .unwrap();

    // TODO Make this some kind of middleware thing
    res.set(MediaType::Json);
    match req.origin.headers.get::<header::AcceptEncoding>() {
        Some(header) => {
            if header.contains(&qitem(header::Encoding::Gzip)) {
                // Client accepts gzip, go ahead and compress it
                res.set(header::ContentEncoding(vec![header::Encoding::Gzip]));

                let mut encoder = GzEncoder::new(Vec::new(), Compression::Default);
                let _ = encoder.write(json::encode(&result).expect("Failed to serialize").as_bytes());
                return res.send(encoder.finish().unwrap());
            }
        }
        None => ()
    }
    res.send(json::encode(&result).expect("Failed to serialize"))
}


/// Return detailed information about a list of project names
///
/// # Arguments
///
/// * `req` - Request from the client
/// * `res` - Response to be modified
///
/// # Returns
///
/// * A `MiddlewareResult`
///
/// # Request
///
/// * `offset` - Number of results to skip before returning results. Default is 0.
/// * `limit` - Maximum number of results to return. It may return less. Default is 20.
/// * `projects` - Comma separated list of projects.
///
/// # Response
///
/// * JSON response with a list of {'name': value, 'summary': value, ...} entries.
///
/// # Panics
///
/// * Failure to get a database connection
/// * Failure to serialize the response
///
/// # TODO
///
/// * Change the response to be {'projects': [ ... ]}
///
/// The response includes details about the project, the available builds for the project,
/// and the sources used for the builds.
///
/// # Examples
///
/// ```json
/// {"projects":[{"name":"lorax","summary":"Tool for creating the anaconda install images","description":"Lorax is a tool for creating the anaconda install images.\n\nIt also includes livemedia-creator which is used to create bootable livemedia,\nincluding live isos and disk images. It can use libvirtd for the install, or\nAnaconda's image install feature.","homepage":"http://git.fedorahosted.org/git/?p=lorax.git","upstream_vcs":"UPSTREAM_VCS","metadata":{},"builds":[{"epoch":0,"release":"1.el7","arch":"x86_64","build_time":"2016-09-08T19:25:20","changelog":"- Don't log dracut initrd regeneration messages into /tmp/syslog (rvykydal)\n  Related: rhbz#1369439\n- Use imjournal for rsyslogd instead of sharing /dev/log with journal (rvykydal)\n  Resolves: rhbz#1369439","build_config_ref":"BUILD_CONFIG_REF","build_env_ref":"BUILD_ENV_REF","metadata":{"packageName":"lorax"},"source":{"license":"GPLv2+","version":"19.6.78","source_ref":"SOURCE_REF","metadata":{}}}]}],"offset":0,"limit":20}
/// ```
///
pub fn project_info_v0<'mw>(req: &mut Request<BDCSConfig>, mut res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
    let offset: i64;
    let limit: i64;
    {
        let query = req.query();
        offset = query.get("offset").unwrap_or("").parse().unwrap_or(0);
        limit = query.get("limit").unwrap_or("").parse().unwrap_or(20);
    }
    let projects = req.param("projects").unwrap_or("").split(",");

    // Why does passing 'foo' match the route and passing: 'foo.1.1'
    // fail?

    let conn = req.db_conn().expect("Failed to get a database connection from the pool.");
    let mut project_list = Vec::new();
    for proj in projects {
        let result = get_projects_name(&conn, proj, offset, limit);
        match result {
            Ok(projs) => {
                // SQL query could potentially return more than one, so loop.
                for p in projs {
                    // Get the build and source details first
                    let mut build_list = Vec::new();
                    let build_results = get_builds_project_id(&conn, p.id);
                    match build_results {
                        Ok(builds) => {
                            for b in builds {
                                let mut source_metadata: HashMap<String, String> = HashMap::new();
                                let result = get_source_kv_source_id(&conn, b.source_id);
                                match result {
                                    Ok(kvs) => {
                                        for kv in kvs {
                                            source_metadata.entry(kv.key_value).or_insert(kv.val_value);
                                        }
                                    }
                                    Err(err) => println!("Error: {}", err)
                                }

                                let mut source_info: Option<SourceInfo> = None;
                                let result = get_source_id(&conn, b.source_id);
                                match result {
                                    // FIXME Only one possible result, not a Vec
                                    Ok(sources) => {
                                        for s in sources {
                                            source_info = Some(SourceInfo {
                                                                license: s.license,
                                                                version: s.version,
                                                                source_ref: s.source_ref,
                                                                metadata: Some(source_metadata)
                                            });
                                            break;
                                        }
                                    }
                                    Err(err) => println!("Error: {}", err)
                                }

                                let mut build_metadata: HashMap<String, String> = HashMap::new();
                                let result = get_build_kv_build_id(&conn, b.id);
                                match result {
                                    Ok(kvs) => {
                                        for kv in kvs {
                                            build_metadata.entry(kv.key_value).or_insert(kv.val_value);
                                        }
                                    }
                                    Err(err) => println!("Error: {}", err)
                                }

                                build_list.push(BuildInfo {
                                                    epoch:            b.epoch,
                                                    release:          b.release,
                                                    arch:             b.arch,
                                                    build_time:       b.build_time,
                                                    changelog:        String::from_utf8(b.changelog).unwrap_or("".to_string()),
                                                    build_config_ref: b.build_config_ref,
                                                    build_env_ref:    b.build_env_ref,
                                                    metadata:         Some(build_metadata),
                                                    source:           source_info
                                });
                            }
                        }
                        Err(err) => println!("Error: {}", err)
                    }

                    let mut proj_metadata: HashMap<String, String> = HashMap::new();
                    let result_2 = get_project_kv_project_id(&conn, p.id);
                    match result_2 {
                        Ok(kvs) => {
                            for kv in kvs {
                                proj_metadata.entry(kv.key_value).or_insert(kv.val_value);
                            }
                        }
                        Err(err) => println!("Error: {}", err)
                    }

                    project_list.push(ProjectInfo {
                                            name:         p.name,
                                            summary:      p.summary,
                                            description:  p.description,
                                            homepage:     p.homepage,
                                            upstream_vcs: p.upstream_vcs,
                                            metadata:     Some(proj_metadata),
                                            builds:       Some(build_list)
                    });
                }
            }
            Err(err) => println!("Error: {}", err)
        }
    }

    // TODO Make this a helper function for API calls
    let result = ProjectsResult {
                    projects: Some(project_list),
                    offset:   Some(offset),
                    limit:    Some(limit),
                    id:       None,
                    msg:      None
    };

    // TODO Make this some kind of middleware thing
    res.set(MediaType::Json);
    match req.origin.headers.get::<header::AcceptEncoding>() {
        Some(header) => {
            if header.contains(&qitem(header::Encoding::Gzip)) {
                // Client accepts gzip, go ahead and compress it
                res.set(header::ContentEncoding(vec![header::Encoding::Gzip]));

                let mut encoder = GzEncoder::new(Vec::new(), Compression::Default);
                let _ = encoder.write(json::encode(&result).expect("Failed to serialize").as_bytes());
                return res.send(encoder.finish().unwrap());
            }
        }
        None => ()
    }
    res.send(json::encode(&result).expect("Failed to serialize"))
}


/// Return the list of available Recipes
///
/// # Arguments
///
/// * `req` - Request from the client
/// * `res` - Response to be modified
///
/// # Returns
///
/// * A `MiddlewareResult`
///
/// # Request
///
/// * `offset` - Number of results to skip before returning results. Default is 0.
/// * `limit` - Maximum number of results to return. It may return less. Default is 20.
///
/// # Response
///
/// * JSON response with 'recipes' set to a list of names - {'recipes': ["name1", ...]}
///
/// # Panics
///
/// * Failure to serialize the response
///
/// # Examples
///
/// ```json
/// {"recipes":["another","example","foo"]}
/// ```
///
pub fn recipe_list_v0<'mw>(req: &mut Request<BDCSConfig>, mut res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
    let bdcs_config = req.server_data();
    let recipe_path = bdcs_config.recipe_path.to_string() + "*";

    let offset: i64;
    let limit: i64;
    {
        let query = req.query();
        offset = query.get("offset").unwrap_or("").parse().unwrap_or(0);
        limit = query.get("limit").unwrap_or("").parse().unwrap_or(20);
    }

    let mut recipe_list = Vec::new();
    for path in glob(&recipe_path).unwrap().filter_map(Result::ok) {
        // Parse the TOML recipe into a Recipe struct
        let mut input = String::new();
        let mut f = File::open(path).unwrap();
        f.read_to_string(&mut input).unwrap();
        let recipe: RecipeList = toml::decode_str(&input).unwrap();
        recipe_list.push(recipe.name);
    }

    let mut response = HashMap::new();
    response.insert("recipes".to_string(), recipe_list);

    res.set(MediaType::Json);
    res.send(json::encode(&response).expect("Failed to serialize"))
}


/// Return the contents of a recipe or list of recipes
///
/// # Arguments
///
/// * `req` - Request from the client
/// * `res` - Response to be modified
///
/// # Returns
///
/// * A `MiddlewareResult`
///
/// # Request
///
/// * `offset` - Number of results to skip before returning results. Default is 0.
/// * `limit` - Maximum number of results to return. It may return less. Default is 20.
/// * `names` - Comma separated list of recipe names to return
///
/// # Response
///
/// * JSON response with recipe contents, using the recipe name(s) as keys
///
/// # Panics
///
/// * Failure to serialize the response
///
/// # Errors
///
/// * 500: File Open Error
/// * 500: Read Error
///
/// # Examples
///
/// ```json
/// {"example":{"description":"A stunning example","modules":[{"name":"fm-httpd","version":"23.*"},{"name":"fm-php","version":"11.6.*"}],"name":"example","packages":[{"name":"tmux","version":"2.2"}]}}
/// ```
///
pub fn get_recipe_v0<'mw>(req: &mut Request<BDCSConfig>, mut res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
    let bdcs_config = req.server_data();

    let offset: i64;
    let limit: i64;
    {
        let query = req.query();
        offset = query.get("offset").unwrap_or("").parse().unwrap_or(0);
        limit = query.get("limit").unwrap_or("").parse().unwrap_or(20);
    }
    let names = req.param("names").unwrap_or("").split(",");

    // XXX For now the filename matches the name. Later: Better retrieval
    let mut response = HashMap::new();
    for name in names {
        // TODO Needs to be sanitized!
        let recipe_path = bdcs_config.recipe_path.to_string() + name;

        for path in glob(&recipe_path).unwrap().filter_map(Result::ok) {
            // Parse the TOML recipe into a Recipe struct
            let mut input = String::new();
            let mut file = match File::open(&path) {
                Ok(file) => file,
                Err(err) => {
                    println!("Error reading {:?}: {}", path, err);
                    return res.error(StatusCode::InternalServerError, "File Open Error.")
                }
            };
            match file.read_to_string(&mut input) {
                Ok(_) => println!("Read recipe from {:?}", path),
                Err(err) => {
                    println!("Error reading {:?}: {}", path, err);
                    return res.error(StatusCode::InternalServerError, "Read Error.")
                }
            };
            let recipe = match toml::decode_str::<Recipe>(&input) {
                Some(recipe) => recipe,
                None => return res.error(StatusCode::InternalServerError, "Error parsing TOML")
            };

            response.insert(recipe.name.clone().unwrap(), recipe);
        }
    }

    res.set(MediaType::Json);
    res.send(json::encode(&response).expect("Failed to serialize"))
}


/// Save a Recipe
///
/// # Arguments
///
/// * `req` - Request from the client
/// * `res` - Response to be modified
///
/// # Returns
///
/// * A `MiddlewareResult`
///
/// # Request
///
/// * Body of the request should be a JSON encoded Recipe.
/// * `names` - The recipe name to store this recipe under
///
/// # Response
///
/// * 200: Recipe was stored successfully
///
/// # Panics
///
/// * Failure to serialize the response
///
/// # Errors
///
/// * 500: Error parsing JSON
/// * 500: Too many recipe names
/// * 500: File Open Error
/// * 500: Write Error
///
/// # Examples
///
/// ```json
/// {"description":"A stunning example","modules":[{"name":"fm-httpd","version":"23.*"},{"name":"fm-php","version":"11.6.*"}],"name":"example","packages":[{"name":"tmux","version":"2.2"}]}
/// ```
///
pub fn post_recipe_v0<'mw>(req: &mut Request<BDCSConfig>, mut res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
    let bdcs_config = req.server_data();

    // Parse the JSON into Recipe structs (XXX Why does this work here, and not below req.param?)
    let recipe = match req.json_as::<Recipe>() {
        Ok(recipe) => recipe,
        Err(err) => {
            println!("Error parsing JSON: {}", err);
            return res.error(StatusCode::InternalServerError, "Error parsing JSON")
        }
    };
    let recipe_toml = toml::encode::<Recipe>(&recipe);
    println!("{:?}", recipe_toml);

    let name = req.param("name").unwrap_or("");
    if name.find(',') != None {
        // TODO Need to define a common error response for bad API calls
        return res.error(StatusCode::InternalServerError, "Too many names.");
    }

    // TODO Needs to be sanitized!
    let recipe_path = bdcs_config.recipe_path.to_string() + name;
    let mut file = match File::create(&recipe_path) {
        Ok(file) => file,
        Err(err) => {
            println!("Error opening {} for write: {}", recipe_path, err);
            return res.error(StatusCode::InternalServerError, "Error opening file.")
        }
    };
    match file.write_all(toml::encode_str(&recipe_toml).as_bytes()) {
        Ok(_) => println!("Wrote Recipe to {}", recipe_path),
        Err(err) => {
            println!("Error writing {}: {}", recipe_path, err);
            return res.error(StatusCode::InternalServerError, "Error writing file.")
        }
    };

    res.set(StatusCode::Ok);
    res.send("")
}


/// List the available groups (aka modules)
///
/// # Arguments
///
/// * `req` - Request from the client
/// * `res` - Response to be modified
///
/// # Returns
///
/// * A `MiddlewareResult`
///
/// # Request
///
/// * `offset` - Number of results to skip before returning results. Default is 0.
/// * `limit` - Maximum number of results to return. It may return less. Default is 20.
///
/// # Response
///
/// * JSON response with 'modules' set to a list of {"name":value, "group_type":value}
///
/// If the client supports it, the results of this are gzipped before being sent.
///
/// # Panics
///
/// * Failure to get a database connection
/// * Failure to serialize the response
///
/// # Errors
///
/// * 500: Error parsing JSON
/// * 500: Too many recipe names
/// * 500: File Open Error
/// * 500: Write Error
///
/// # Examples
///
/// ```json
/// {"modules":[{"group_type":"rpm","name":"389-ds-base"},{"group_type":"rpm","name":"389-ds-base-libs"},{"group_type":"rpm","name":"ElectricFence"},{"group_type":"rpm","name":"ElectricFence"},{"group_type":"rpm","name":"GConf2"},{"group_type":"rpm","name":"GConf2"},{"group_type":"rpm","name":"GeoIP"},{"group_type":"rpm","name":"GeoIP"},{"group_type":"rpm","name":"ImageMagick"},{"group_type":"rpm","name":"ImageMagick"},{"group_type":"rpm","name":"ImageMagick-c++"},{"group_type":"rpm","name":"ImageMagick-c++"},{"group_type":"rpm","name":"ImageMagick-perl"},{"group_type":"rpm","name":"LibRaw"},{"group_type":"rpm","name":"LibRaw"},{"group_type":"rpm","name":"ModemManager"},{"group_type":"rpm","name":"ModemManager-glib"},{"group_type":"rpm","name":"ModemManager-glib"},{"group_type":"rpm","name":"MySQL-python"},{"group_type":"rpm","name":"NetworkManager"}]}
/// ```
///
pub fn group_list_v0<'mw>(req: &mut Request<BDCSConfig>, mut res: Response<'mw, BDCSConfig>) -> MiddlewareResult<'mw, BDCSConfig> {
    let offset: i64;
    let limit: i64;
    {
        let query = req.query();
        offset = query.get("offset").unwrap_or("").parse().unwrap_or(0);
        limit = query.get("limit").unwrap_or("").parse().unwrap_or(20);
    }

    // List all groups if there is no groups param or if it is empty.
    let groups = match req.param("groups") {
        Some(groups) => if groups.len() > 0 { groups } else {"*"},
        None => "*"
    };

    let conn = req.db_conn().expect("Failed to get a database connection from the pool.");
    let mut group_list = Vec::new();
    for group in groups.split(",") {
        let result = get_groups_name(&conn, group, offset, limit);
        match result {
            Ok(grps) => {
                // SQL query could potentially return more than one, so loop.
                for g in grps {
                    group_list.push(g);
                }
            }
            Err(err) => println!("Error: {}", err)
        }
    }
    res.set(MediaType::Json);

    let mut response = HashMap::new();
    response.insert("modules".to_string(), group_list);

    // TODO Make this some kind of middleware thing
    match req.origin.headers.get::<header::AcceptEncoding>() {
        Some(header) => {
            if header.contains(&qitem(header::Encoding::Gzip)) {
                // Client accepts gzip, go ahead and compress it
                res.set(header::ContentEncoding(vec![header::Encoding::Gzip]));

                let mut encoder = GzEncoder::new(Vec::new(), Compression::Default);
                let _ = encoder.write(json::encode(&response).expect("Failed to serialize").as_bytes());
                return res.send(encoder.finish().unwrap());
            }
        }
        None => ()
    }
    res.send(json::encode(&response).expect("Failed to serialize"))
}
