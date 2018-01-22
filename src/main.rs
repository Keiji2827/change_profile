extern crate libc;
extern crate regex;
use libc::{pid_t, getpid};
use std::fs::{File, OpenOptions};
use std::io::BufReader;
use std::io::prelude::*;
//use regex::Regex;
#[derive(PartialEq, Eq)]
enum SecurityApp{AppArmor, SELinux, None}

fn change_profile(profile : String) -> Result<u32, String>{
    // confirm if profile is empty
    if profile.is_empty(){
        Err("Enter profile name".to_owned())
    }

    else {
        let buf;
        let sel = try!(checksecurity());
        match sel {
            // merge "changeprofile + profile"
            SecurityApp::AppArmor => buf = format!("changeprofile {}", profile),
            SecurityApp::SELinux  => buf = format!("{}", profile),
            SecurityApp::None     => {println!("There is no security package working.");return Ok(0)},
        }
        println!("You will execute \"{}\"", &buf);

        // call setprocattr
        match setprocattr(unsafe{ getpid()}, "current".to_string(), buf){
            Err(er) => Err(er),
            Ok(_) => Ok(0)
        }
    }
}

fn checksecurity() -> Result<SecurityApp, String> {
    let aa_path = "/sys/module/apparmor/parameters/enabled";
    let se_path = "/proc/filesystems";
    let mut select = SecurityApp::None;

    if let Ok(file) = File::open(aa_path) {
        let mut reader = BufReader::new(file);
        let mut contents = String::new();
        if let Ok(_) = reader.read_to_string(&mut contents) {
            println!("{:?}", &contents);
            match &*contents {
                "Y" => select = SecurityApp::AppArmor,
                &_  => {},
            }
        }
    }

    if select == SecurityApp::AppArmor {
        return Ok(select);
    }

    // checking SELinux
    if let Ok(file) = File::open(se_path) {
        let mut reader = BufReader::new(file);
        // search for selinux 
        for line in reader.lines() {
            let l = line.unwrap();
            if l.contains("selinux") {
                println!("found selinux");
                select = SecurityApp::SELinux;
                break;
            }
        }
    }
    if select == SecurityApp::SELinux {
        return Ok(select);
    }
    
    Ok(select)

}

fn setprocattr(tid : pid_t, attr : String, buf : String) -> Result<u32, String> {

    // to call proattr_path
    let ctl = try!(procattr_path(tid, attr));
    
    // file open
    //let mut fd = match File::create(ctl) {
    let mut fd = match OpenOptions::new().write(true).open(ctl) {
        Err(_) => panic!("File couldn't be opened"),
        Ok(file) => file,
    };
    // write to file
    match fd.write_fmt(format_args!("{}", buf)) {
        Err(er) => Err(er.to_string()),
        Ok(_)   => Ok(0)
    }
}

fn procattr_path(pid : pid_t, attr : String) -> Result<String, String> {
    let path = format!("/proc/{}/attr/{}", pid, attr);
    Ok(path)
}

fn main() {

    let profile = "sample_profile";
    let ret = change_profile(profile.to_owned());
    match ret {
        Err(err) => println!("{}", err),
        Ok(n)    => println!("{}", n)
    }
}
