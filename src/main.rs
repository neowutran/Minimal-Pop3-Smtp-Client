use base64;
use docopt::Docopt;
use openssl::ssl::{SslConnector, SslMethod, SslStream};
use regex::Regex;
use serde::Deserialize;
use std::{
    error::Error, fs, fs::File, io, io::prelude::*, net::TcpStream, path::Path, process::Command,
};
static NEWLINE: &str = "\r\n";
static LF: u8 = 0x0A;
static CR: u8 = 0x0D;
static DOT: u8 = 46;
fn is_success_pop(server_response: &str) -> bool {
    server_response.starts_with("+OK")
}
fn write(stream: &mut SslStream<TcpStream>, command_str: &str) -> Result<(), Box<dyn Error>> {
    stream.ssl_write(format!("{}{}", command_str, NEWLINE).as_bytes())?;
    Ok(())
}
fn write_unencrypted(stream: &mut TcpStream, command_str: &str) -> Result<(), Box<dyn Error>> {
    stream.write(format!("{}{}", command_str, NEWLINE).as_bytes())?;
    Ok(())
}
fn read_block(stream: &mut SslStream<TcpStream>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut block = vec![0; 512];
    let size = stream.ssl_read(&mut block)?;
    block.resize(size, 0);
    Ok(block)
}
fn read_blocks(stream: &mut SslStream<TcpStream>) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
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
fn read_multiline_smtp(stream: &mut SslStream<TcpStream>) -> Result<String, Box<dyn Error>> {
    //  It doesn't follow the rfc: https://tools.ietf.org/html/rfc821#page-51
    //  It is way simpler, and should handle all of my personal use cases
    let full: String = String::from_utf8((&read_block(stream)?).to_vec())?;
    let segments: Vec<&str> = full.lines().collect();
    Ok(segments.join(&"\n"))
}
fn flush(to_fill: &mut Vec<u8>, to_empty: &mut Vec<u8>) {
    to_fill.append(to_empty);
    to_empty.clear();
}
fn read_singleline(stream: &mut SslStream<TcpStream>) -> Result<String, Box<dyn Error>> {
    Ok(String::from(
        String::from_utf8((&read_block(stream)?).to_vec())?
            .lines()
            .nth(0)
            .unwrap(),
    ))
}
fn read_unencrypted_singleline(stream: &mut TcpStream) -> Result<String, Box<dyn Error>> {
    let mut block = vec![0; 512];
    let size = stream.read(&mut block)?;
    block.resize(size, 0);
    Ok(String::from(
        String::from_utf8((&block).to_vec())?
            .lines()
            .nth(0)
            .unwrap(),
    ))
}
fn read_multiline_pop(stream: &mut SslStream<TcpStream>) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let message_lines = read_blocks(stream)?;
    let status_line = String::from_utf8((&message_lines[0]).to_vec())?;
    println!("{}", status_line);
    if !is_success_pop(&status_line) {
        panic!();
    }
    Ok(message_lines[1..].to_vec())
}
fn singleline_command(
    stream: &mut SslStream<TcpStream>,
    command: &str,
) -> Result<(), Box<dyn Error>> {
    write(stream, command)?;
    println!("{}", read_singleline(stream)?);
    Ok(())
}
struct Account {
    host: String,
    port: u32,
    user: String,
    tls: Tls,
    password: String,
    maildir: String,
    protocol: Protocol,
}
#[derive(PartialEq)]
enum Tls {
    StartTls,
    Tls,
}
#[derive(PartialEq)]
enum Protocol {
    Pop,
    Smtp,
}
fn biggest_mail_number(directory: &str) -> u32 {
    let paths = fs::read_dir(directory).unwrap();
    let mut biggest = 0;
    for path in paths {
        let path = path.unwrap().path();
        let path_string = path.file_name().unwrap().to_str().unwrap();
        let name: Vec<&str> = path_string.split(':').collect();
        let current: u32 = name[0].parse().unwrap();
        if current > biggest {
            biggest = current;
        }
    }
    biggest
}
fn default_account() -> Account {
    Account {
        host: String::from(""),
        user: String::from(""),
        port: 995,
        tls: Tls::Tls,
        protocol: Protocol::Pop,
        password: String::from(""),
        maildir: String::from(""),
    }
}

fn set_password(account: &mut Account) -> Result<(), Box<dyn Error>> {
    if !Regex::new(
        r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
    )?
    .is_match(&account.user)
    {
        panic!(format!("{} is not a valid email adresse", account.user));
    }
    let inbox_directory = format!("/home/user/mail/{}/INBOX", account.user);
    fs::create_dir_all(&inbox_directory)?;
    account.maildir = inbox_directory;
    let eval = Command::new("/bin/bash")
        .arg("-c")
        .arg(&format!(
            "/usr/bin/qubes-gpg-client-wrapper --quiet --no-tty --decrypt /home/user/mail/{}/pass.asc",
            account.user
        ))
        .output()?;
    if !eval.status.success() {
        panic!(format!(
            "Unable read password: {}",
            String::from_utf8(eval.stderr)?
        ));
    }
    account.password = String::from_utf8(eval.stdout)?
        .lines()
        .nth(0)
        .unwrap()
        .to_string();
    Ok(())
}
fn read_config() -> Result<Vec<Account>, Box<dyn Error>> {
    let mut all_accounts = Vec::new();
    let mut account = default_account();
    let mut file = File::open("/home/user/.pop_smtp")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    for line in contents.lines() {
        if line.is_empty() {
            set_password(&mut account)?;
            all_accounts.push(account);
            account = default_account();
            continue;
        }
        let config_line: Vec<&str> = line.splitn(2, ' ').collect();
        let key = config_line.get(0).unwrap();
        let value = config_line.get(1).unwrap();
        match key{
          &"host" => account.host = value.to_string(),
          &"user" => account.user = value.to_string(),
          &"port" => account.port = value.parse()?,
          &"tls" => match value{
            &"tls" => account.tls = Tls::Tls,
            &"starttls" => account.tls = Tls::StartTls,
            _ => panic!(format!("{} doesn't exist for config 'tls'. Only 'tls' and 'starttls' are acceptable values", value)),
          },
          &"protocol" => match value{
            &"pop" => account.protocol = Protocol::Pop,
            &"smtp" => account.protocol = Protocol::Smtp,
            _ => panic!(format!("{} doesn't exist for config 'protocol'. Only 'pop' and 'smtp' are acceptable values", value))
          }
          _ => panic!(format!("{} is not a known config key", key)),
        }
    }
    set_password(&mut account)?;
    all_accounts.push(account);
    Ok(all_accounts)
}
fn download_mail(
    account: &Account,
    tls_stream: &mut SslStream<TcpStream>,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(&format!("{}/cur", &account.maildir))?;
    fs::create_dir_all(&format!("{}/new", &account.maildir))?;
    fs::create_dir_all(&format!("{}/tmp", &account.maildir))?;
    singleline_command(tls_stream, &format!("user {}", &account.user))?;
    singleline_command(tls_stream, &format!("pass {}", &account.password))?;

    write(tls_stream, "stat")?;
    let stat = read_singleline(tls_stream)?;
    let stat_segments: Vec<&str> = stat.split(' ').collect();
    let biggest_message_number: u32 = stat_segments.get(1).unwrap().parse()?;
    let size_in_octets: u64 = stat_segments.get(2).unwrap().parse()?;
    println!(
        "{} messages, {:.2} Mo",
        biggest_message_number,
        size_in_octets as f64 / 1_000_000.0
    );
    let cur_biggest = biggest_mail_number(&format!("{}/cur", &account.maildir));
    let new_biggest = biggest_mail_number(&format!("{}/new", &account.maildir));
    let mut biggest = cur_biggest;
    if new_biggest > cur_biggest {
        biggest = new_biggest;
    }
    if biggest == biggest_message_number {
        println!("No new messages");
        return Ok(());
    }
    for message in biggest + 1..biggest_message_number + 1 {
        let tmp_filename = format!("{}/tmp/{}", account.maildir, message);
        let filename = format!("{}/new/{}", account.maildir, message);
        {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(&tmp_filename)?;
            write(tls_stream, &format!("retr {}", message))?;
            file.write_all(&read_multiline_pop(tls_stream)?.join(&LF))?;
        }
        if Path::new(&filename).exists() {
            fs::remove_file(&filename)?;
        }
        fs::hard_link(&tmp_filename, &filename)?;
        fs::remove_file(&tmp_filename)?;
    }
    Ok(())
}
fn send_mail(
    account: &Account,
    tls_stream: &mut SslStream<TcpStream>,
    from: &str,
    to: &Vec<String>,
) -> Result<(), Box<dyn Error>> {
    write(tls_stream, &format!("ehlo {}", &account.host))?;
    println!("{}", read_multiline_smtp(tls_stream)?);
    write(tls_stream, "auth login")?;
    println!("{}", read_singleline(tls_stream)?);
    write(tls_stream, &format!("{}", base64::encode(&account.user)))?;
    println!("{}", read_singleline(tls_stream)?);
    write(
        tls_stream,
        &format!("{}", base64::encode(&account.password)),
    )?;
    println!("{}", read_singleline(tls_stream)?);
    singleline_command(tls_stream, &format!("mail from:<{}>", from))?;
    for recipient in to {
        singleline_command(tls_stream, &format!("rcpt to:<{}>", &recipient))?;
    }
    let mut data = String::new();
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    handle.read_to_string(&mut data)?;
    write(tls_stream, "data")?;
    println!("{}", read_singleline(tls_stream)?);
    write(tls_stream, &format!("{}\r\n.\r\n", data))?;
    println!("{}", read_singleline(tls_stream)?);

    Ok(())
}
fn pop_smtp(
    account: &Account,
    connector: &SslConnector,
    args: &Args,
) -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect(&format!("{}:{}", &account.host, &account.port))?;
    if account.tls == Tls::StartTls {
        println!("{}", read_unencrypted_singleline(&mut stream)?);
        match account.protocol {
            Protocol::Pop => write_unencrypted(&mut stream, "stls")?,
            Protocol::Smtp => write_unencrypted(&mut stream, "starttls")?,
        }
        println!("{}", read_unencrypted_singleline(&mut stream)?);
    }
    let mut tls_stream = connector.connect(&account.host, stream)?;
    if account.tls == Tls::Tls {
        println!("{}", read_singleline(&mut tls_stream)?);
    }
    match account.protocol {
        Protocol::Pop => download_mail(account, &mut tls_stream)?,
        Protocol::Smtp => send_mail(account, &mut tls_stream, &args.flag_from, &args.arg_to)?,
    }
    singleline_command(&mut tls_stream, "quit")?;
    Ok(())
}
const USAGE: &'static str = "
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
    if !args.flag_account.is_empty() {
        for account in accounts {
            if account.user == args.flag_account && account.protocol == Protocol::Smtp {
                pop_smtp(&account, &connector, &args)?;
                return Ok(());
            }
        }
        panic!(format!("Account {} not found", args.flag_account));
    } else {
        for account in accounts {
            if account.protocol == Protocol::Pop {
                pop_smtp(&account, &connector, &args)?;
            }
        }
    }
    Ok(())
}
