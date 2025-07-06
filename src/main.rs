#![forbid(unsafe_code)]
#![deny(clippy::mem_forget)]

use base64::{engine::general_purpose, Engine as _};
use docopt::Docopt;
use openssl::ssl::{SslConnector, SslMethod, SslStream};
use regex::Regex;
use serde::Deserialize;
use std::{
    cmp::Ordering, error::Error, fs, fs::File, io, io::prelude::*, net::TcpStream, path::Path,
    process::Command,
};
use zeroize::Zeroize;
static NEWLINE: &str = "\r\n";
static LF: u8 = 0x0A;
static CR: u8 = 0x0D;
static DOT: u8 = 46;
fn is_success_pop(server_response: &str) -> bool {
    server_response.starts_with("+OK")
}
fn write(stream: &mut Stream, command_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    match stream {
        Stream::TlsStream(x) => {
            x.ssl_write(command_bytes)?;
        }
        Stream::UnencryptedStream(x) => {
            x.write_all(command_bytes)?;
        }
    }
    Ok(())
}
fn write_line(stream: &mut Stream, command_str: &str) -> Result<(), Box<dyn Error>> {
    let command = format!("{command_str}{NEWLINE}");
    write(stream, command.as_bytes())
}
fn read_block(stream: &mut Stream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut block = vec![0; 512];
    let size = match stream {
        Stream::TlsStream(x) => x.ssl_read(&mut block)?,
        Stream::UnencryptedStream(x) => x.read(&mut block)?,
    };
    block.resize(size, 0);
    Ok(block)
}
fn read_blocks(stream: &mut Stream) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut result = Vec::new();
    let mut current_line = Vec::new();
    let mut newline_buffer = Vec::new();
    loop {
        let block = read_block(stream)?;
        for byte in block {
            if byte == CR {
                if newline_buffer.len() == 1 && newline_buffer[0] != DOT {
                    flush(&mut current_line, &mut newline_buffer);
                }
                newline_buffer.push(byte);
            } else if byte == LF {
                if newline_buffer.len() == 1 && newline_buffer[0] == CR {
                    result.push(current_line);
                    current_line = Vec::new();
                    newline_buffer = Vec::new();
                } else if newline_buffer.len() == 2 {
                    return Ok(result);
                }
            } else {
                flush(&mut current_line, &mut newline_buffer);
                if byte == DOT && current_line.is_empty() {
                    if newline_buffer.is_empty() {
                        newline_buffer.push(byte);
                    }
                } else {
                    current_line.push(byte);
                }
            }
        }
    }
}
fn read_multiline_smtp(stream: &mut Stream) -> Result<String, Box<dyn Error>> {
    //  It doesn't follow the rfc: https://tools.ietf.org/html/rfc821#page-51
    //  It is way simpler, and should handle all of my personal use cases
    let full: String = String::from_utf8(read_block(stream)?)?;
    let segments: Vec<&str> = full.lines().collect();
    Ok(segments.join("\n"))
}
fn flush(to_fill: &mut Vec<u8>, to_empty: &mut Vec<u8>) {
    to_fill.append(to_empty);
    to_empty.clear();
}
fn read_singleline(stream: &mut Stream) -> Result<String, Box<dyn Error>> {
    Ok(String::from(
        String::from_utf8(read_block(stream)?)?
            .lines()
            .next()
            .ok_or("The line must exist")?,
    ))
}
fn read_multiline_pop(stream: &mut Stream) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let message_lines = read_blocks(stream)?;
    let status_line = String::from_utf8(message_lines[0].clone())?;
    println!("{status_line}");
    assert!(is_success_pop(&status_line),);
    Ok(message_lines[1..].to_vec())
}
fn singleline_command(stream: &mut Stream, command: &str) -> Result<(), Box<dyn Error>> {
    write_line(stream, command)?;
    println!("{}", read_singleline(stream)?);
    Ok(())
}
enum Stream {
    TlsStream(SslStream<TcpStream>),
    UnencryptedStream(TcpStream),
}
struct Account {
    host: String,
    port: u32,
    user: String,
    tls: Tls,
    maildir: String,
    protocol: Protocol,
}
#[derive(PartialEq)]
enum Tls {
    StartTls,
    Tls,
    None,
}
#[derive(PartialEq)]
enum Protocol {
    Pop,
    Smtp,
}
fn biggest_mail_number(directory: &str) -> Result<u32, Box<dyn Error>> {
    let paths = fs::read_dir(directory)?;
    let mut biggest = 0;
    for path in paths {
        let path = path?.path();
        let path_string = path
            .file_name()
            .ok_or("Filename must exist")?
            .to_str()
            .ok_or("Filename must exist")?;
        let name: Vec<&str> = path_string.split(':').collect();
        let current: u32 = name[0].parse()?;
        if current > biggest {
            biggest = current;
        }
    }
    Ok(biggest)
}
const fn default_account() -> Account {
    Account {
        host: String::new(),
        user: String::new(),
        port: 995,
        tls: Tls::Tls,
        protocol: Protocol::Pop,
        maildir: String::new(),
    }
}

fn check_account(account: &mut Account) -> Result<(), Box<dyn Error>> {
    if !Regex::new(
        r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
    )?
    .is_match(&account.user)
    {
        panic!("{} is not a valid email adresse", account.user);
    }
    let inbox_directory = format!("/home/user/mail/{}/INBOX", account.user);
    fs::create_dir_all(&inbox_directory)?;
    account.maildir = inbox_directory;
    Ok(())
}

fn get_password(account: &Account) -> Result<String, Box<dyn Error>> {
    println!("GPG qube request: ASKING");
    let eval = Command::new("/bin/bash")
        .arg("-c")
        .arg(format!(
            "/usr/bin/qubes-gpg-client-wrapper --quiet --no-tty --decrypt /home/user/mail/{}/pass.asc",
            account.user
        ))
        .output()?;
    println!("GPG qube request: DONE");
    assert!(
        eval.status.success(),
        "Unable read password: {}",
        String::from_utf8(eval.stderr)?
    );
    Ok(String::from_utf8(eval.stdout)?
        .lines()
        .next()
        .ok_or("Unable to read the password")?
        .to_string())
}
fn read_config() -> Result<Vec<Account>, Box<dyn Error>> {
    let mut all_accounts = Vec::new();
    let mut account = default_account();
    let mut file = File::open("/home/user/.pop_smtp")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    for line in contents.lines() {
        if line.is_empty() {
            check_account(&mut account)?;
            all_accounts.push(account);
            account = default_account();
            continue;
        }
        let config_line: Vec<&str> = line.splitn(2, ' ').collect();
        let key = config_line
            .first()
            .ok_or("Invalid config line structure. Expecting 'xxx xxx'")?;
        let value = config_line
            .get(1)
            .ok_or("Invalid config line structure. Expecting 'xxx xxx'")?;
        match *key{
          "host" => account.host = (*value).to_string(),
          "user" => account.user = (*value).to_string(),
          "port" => account.port = value.parse()?,
          "tls" => match *value{
            "tls" => account.tls = Tls::Tls,
            "starttls" => account.tls = Tls::StartTls,
            "none" => account.tls = Tls::None,
            _ => panic!("{value} doesn't exist for config 'tls'. Only 'tls' and 'starttls' are acceptable values"),
          },
          "protocol" => match *value{
            "pop" => account.protocol = Protocol::Pop,
            "smtp" => account.protocol = Protocol::Smtp,
            _ => panic!("{value} doesn't exist for config 'protocol'. Only 'pop' and 'smtp' are acceptable values")
          }
          _ => panic!("{key} is not a known config key"),
        }
    }
    assert!(
        !(account.tls == Tls::None && account.host != "127.0.0.1"),
        "Absence of encryption is only allowed for 127.0.0.1"
    );
    check_account(&mut account)?;
    all_accounts.push(account);
    Ok(all_accounts)
}

#[allow(clippy::cast_precision_loss)]
fn download_mail(account: &Account, stream: &mut Stream) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(format!("{}/cur", &account.maildir))?;
    fs::create_dir_all(format!("{}/new", &account.maildir))?;
    fs::create_dir_all(format!("{}/tmp", &account.maildir))?;
    singleline_command(stream, &format!("user {}", &account.user))?;

    let mut password = get_password(account)?;
    let mut password_command = format!("pass {}", &password);
    singleline_command(stream, &password_command)?;
    password.zeroize();
    password_command.zeroize();

    write_line(stream, "stat")?;
    let stat = read_singleline(stream)?;
    let stat_segments: Vec<&str> = stat.split(' ').collect();
    let biggest_message_number: u32 = stat_segments
        .get(1)
        .ok_or("Invalid response to 'stat' command. Expecting space delimited response")?
        .parse()?;
    let size_in_octets: u64 = stat_segments
        .get(2)
        .ok_or("Invalid response to 'stat' command. Expecting space delimited reponse")?
        .parse()?;
    println!(
        "{biggest_message_number} messages, {:.2} Mo",
        size_in_octets as f64 / 1_000_000.0
    );
    let cur_biggest = biggest_mail_number(&format!("{}/cur", &account.maildir))?;
    let new_biggest = biggest_mail_number(&format!("{}/new", &account.maildir))?;
    let biggest = if new_biggest > cur_biggest {
        new_biggest
    } else {
        cur_biggest
    };
    match biggest.cmp(&biggest_message_number) {
        Ordering::Equal => {
            println!("No new messages");
            Ok(())
        }
        Ordering::Greater => panic!(
            "Some mail have been deleted on your mail server and only remain in your local folder."
        ),
        Ordering::Less => {
            for message in biggest + 1..=biggest_message_number {
                let tmp_filename = format!("{}/tmp/{message}", account.maildir);
                let filename = format!("{}/new/{message}", account.maildir);
                {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&tmp_filename)?;
                    write_line(stream, &format!("retr {message}"))?;
                    file.write_all(&read_multiline_pop(stream)?.join(&LF))?;
                }
                if Path::new(&filename).exists() {
                    fs::remove_file(&filename)?;
                }
                fs::hard_link(&tmp_filename, &filename)?;
                fs::remove_file(&tmp_filename)?;
            }
            Ok(())
        }
    }
}
fn send_mail(
    account: &Account,
    stream: &mut Stream,
    from: &str,
    to: &[String],
) -> Result<(), Box<dyn Error>> {
    write_line(stream, &format!("ehlo {}", &account.host))?;
    println!("{}", read_multiline_smtp(stream)?);
    write_line(stream, "auth login")?;
    println!("{}", read_singleline(stream)?);
    write_line(stream, &general_purpose::STANDARD.encode(&account.user))?;
    println!("{}", read_singleline(stream)?);

    let mut password = get_password(account)?;
    let mut password_command = general_purpose::STANDARD.encode(&password);
    write_line(stream, &password_command)?;
    password.zeroize();
    password_command.zeroize();

    println!("{}", read_singleline(stream)?);
    singleline_command(stream, &format!("mail from:<{from}>"))?;
    for recipient in to {
        singleline_command(stream, &format!("rcpt to:<{}>", &recipient))?;
    }
    let mut data = Vec::new();
    let stdin = io::stdin();
    stdin.lock().read_to_end(&mut data)?;
    write_line(stream, "data")?;
    println!("{}", read_singleline(stream)?);

    for bytes in data.chunks(1024) {
        write(stream, bytes)?;
    }

    write_line(stream, &format!("{NEWLINE}."))?;
    println!("{}", read_singleline(stream)?);

    Ok(())
}
fn pop_smtp(
    account: &Account,
    connector: &SslConnector,
    args: &Args,
) -> Result<(), Box<dyn Error>> {
    let mut unencrypted_stream = Stream::UnencryptedStream(TcpStream::connect(format!(
        "{}:{}",
        &account.host, &account.port
    ))?);
    if account.tls == Tls::StartTls {
        println!("{}", read_singleline(&mut unencrypted_stream)?);
        match account.protocol {
            Protocol::Pop => write_line(&mut unencrypted_stream, "stls")?,
            Protocol::Smtp => write_line(&mut unencrypted_stream, "starttls")?,
        }
        println!("{}", read_singleline(&mut unencrypted_stream)?);
    }
    let mut generic_stream = if account.tls == Tls::None {
        unencrypted_stream
    } else {
        match unencrypted_stream {
            Stream::UnencryptedStream(x) => Stream::TlsStream(connector.connect(&account.host, x)?),
            Stream::TlsStream(_) => panic!("impossible case"),
        }
    };
    if account.tls == Tls::Tls {
        println!("{}", read_singleline(&mut generic_stream)?);
    }
    match account.protocol {
        Protocol::Pop => download_mail(account, &mut generic_stream)?,
        Protocol::Smtp => send_mail(account, &mut generic_stream, &args.flag_from, &args.arg_to)?,
    }
    singleline_command(&mut generic_stream, "quit")?;
    Ok(())
}
const USAGE: &str = "
pop_smtp client for neomutt.

Usage:
  pop_smtp
  pop_smtp -a ACCOUNT -f SOURCE [--] <to>...
  pop_smtp (-h | --help)
  pop_smtp --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  -f SOURCE --from=SOURCE     Source email.
  -a ACCOUNT --account=ACCOUNT   Account.
";
#[derive(Debug, Deserialize)]
struct Args {
    arg_to: Vec<String>,
    flag_from: String,
    flag_account: String,
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
    let accounts = read_config()?;
    let connector = SslConnector::builder(SslMethod::tls())?.build();
    if args.flag_account.is_empty() {
        for account in accounts {
            if account.protocol == Protocol::Pop {
                pop_smtp(&account, &connector, &args)?;
            }
        }
    } else {
        for account in accounts {
            if account.user == args.flag_account && account.protocol == Protocol::Smtp {
                pop_smtp(&account, &connector, &args)?;
                return Ok(());
            }
        }
        panic!("Account {} not found", args.flag_account);
    }
    Ok(())
}
