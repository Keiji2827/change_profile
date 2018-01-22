extern crate libc;
extern crate regex;
use libc::{pid_t, getpid};
use std::fs::File;
use std::io::prelude::*;
use regex::Regex;

enum SecurityApp{AppArmor, SELinux,}

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
    let select;

    // open AppArmor enabled file
    let mut aa_fd = File::open(aa_path);

    match aa_fd {
        Ok(mut file) => {
            let mut contents = String::new();
            file.read_to_string(&mut contents);
            println!("{:?}",contents);
            Ok(SecurityApp::AppArmor)
        },
        Err(_)   => {
            let mut se_fd = File::open(se_path);
            match se_fd {
                Ok(mut file2) => {
                    let mut contents2 = String::new();
                    file2.read_to_string(&mut contents2);
                    println!("{:?}",contents2);
                    Ok(SecurityApp::AppArmor)
                }
                Err(_) => Err("both do not work.".to_string())
            }
        }
    }
}

fn setprocattr(tid : pid_t, attr : String, buf : String) -> Result<u32, String> {

    // to call proattr_path
    let ctl = try!(procattr_path(tid, attr));
    
    // file open
    let mut fd = match File::open(ctl) {
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
