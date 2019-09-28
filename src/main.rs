use openssl::ssl::{SslConnector, SslMethod, SslStream};
use std::{
    error::Error, fs, fs::File, io::prelude::*, net::TcpStream, path::Path, process::Command,
};
// https://tools.ietf.org/html/rfc1939
static NEWLINE: &str = "\r\n";
static LF: u8 = 0x0A;
static CR: u8 = 0x0D;
static DOT: u8 = 46;

fn is_success(server_response: &str) -> bool {
    server_response.starts_with("+OK")
}

fn write(stream: &mut SslStream<TcpStream>, command_str: &str) -> Result<(), Box<dyn Error>> {
    stream.ssl_write(format!("{}{}", command_str, NEWLINE).as_bytes())?;
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

fn read_multiline(stream: &mut SslStream<TcpStream>) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let message_lines = read_blocks(stream)?;
    let status_line = String::from_utf8((&message_lines[0]).to_vec())?;
    println!("{}", status_line);
    if !is_success(&status_line) {
        panic!();
    }
    Ok(message_lines[1..].to_vec())
}

fn stat(stream: &mut SslStream<TcpStream>) -> Result<u32, Box<dyn Error>> {
    write(stream, "stat")?;
    let stat = read_singleline(stream)?;
    let stat_segments: Vec<&str> = stat.split(' ').collect();
    let number_of_messages: u32 = stat_segments.get(1).unwrap().parse()?;
    let size_in_octets: u64 = stat_segments.get(2).unwrap().parse()?;
    println!(
        "{} messages, {:.2} Mo",
        number_of_messages,
        size_in_octets as f64 / 1_000_000.0
    );
    Ok(number_of_messages)
}

fn user(stream: &mut SslStream<TcpStream>, username: &str) -> Result<String, Box<dyn Error>> {
    write(stream, &format!("user {}", username))?;
    Ok(read_singleline(stream)?)
}

fn pass(stream: &mut SslStream<TcpStream>, password: &str) -> Result<String, Box<dyn Error>> {
    write(stream, &format!("pass {}", password))?;
    Ok(read_singleline(stream)?)
}

fn quit(stream: &mut SslStream<TcpStream>) -> Result<String, Box<dyn Error>> {
    write(stream, "quit")?;
    Ok(read_singleline(stream)?)
}

fn retr(stream: &mut SslStream<TcpStream>, message_number: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    write(stream, &format!("retr {}", message_number))?;
    Ok(read_multiline(stream)?.join(&LF))
}
struct Account {
    host: String,
    port: u32,
    user: String,
    password: String,
    maildir: String,
}

fn real_dir(link: &str) -> String {
    String::from_utf8(
        Command::new("bash")
            .arg("-c")
            .arg(&format!("mkdir -p {};readlink -f {}", link, link))
            .output()
            .expect("failed to execute process")
            .stdout,
    )
    .unwrap()
    .lines()
    .nth(0)
    .expect(&format!("{} doesn't exist", link))
    .to_string()
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

fn read_config() -> Result<Vec<Account>, Box<dyn Error>> {
    let mut all_accounts = Vec::new();
    let mut account = Account {
        host: String::from(""),
        user: String::from(""),
        port: 995,
        password: String::from(""),
        maildir: String::from(""),
    };
    let mut file = File::open(&real_dir("~/.pop"))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    for line in contents.lines() {
        if line.is_empty() {
            all_accounts.push(account);
            account = Account {
                host: String::from(""),
                user: String::from(""),
                port: 995,
                password: String::from(""),
                maildir: String::from(""),
            };
            continue;
        }
        let config_line: Vec<&str> = line.splitn(2, ' ').collect();
        let key = config_line.get(0).unwrap();
        let value = config_line.get(1).unwrap();
        if key == &"host" {
            account.host = value.to_string();
        } else if key == &"user" {
            account.user = value.to_string();
        } else if key == &"port" {
            account.port = value.parse().unwrap();
        } else if key == &"maildir" {
            account.maildir = real_dir(value);
            if !Path::new(&account.maildir).exists() {
                panic!("Directory {} doesn't exist!", account.maildir);
            }
        } else if key == &"password" {
            let command = value.to_string();
            let eval = Command::new("bash")
                .arg("-c")
                .arg(&command)
                .output()
                .expect("failed to execute process");
            if !eval.status.success() {
                panic!(format!(
                    "Unable to execute command: {}; {}",
                    &command,
                    String::from_utf8(eval.stderr)?
                ));
            }
            account.password = String::from_utf8(eval.stdout)?
                .lines()
                .nth(0)
                .unwrap()
                .to_string();
        } else {
            panic!(format!("{} is not a known config key", key));
        }
    }
    all_accounts.push(account);
    Ok(all_accounts)
}

fn create_maildir_folder(base_directory: &str) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(&format!("{}/cur", base_directory))?;
    fs::create_dir_all(&format!("{}/new", base_directory))?;
    fs::create_dir_all(&format!("{}/tmp", base_directory))?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    for account in read_config()? {
        create_maildir_folder(&account.maildir)?;
        let connector = SslConnector::builder(SslMethod::tls())?.build();
        let stream = TcpStream::connect(&format!("{}:{}", &account.host, &account.port))?;
        let mut stream = connector.connect(&account.host, stream)?;
        println!("{}", read_singleline(&mut stream)?);
        println!("{}", user(&mut stream, &account.user)?);
        println!("{}", pass(&mut stream, &account.password)?);
        let number_of_messages = stat(&mut stream)?;

        let cur_biggest = biggest_mail_number(&format!("{}/cur", &account.maildir));
        let new_biggest = biggest_mail_number(&format!("{}/new", &account.maildir));
        let mut biggest = cur_biggest;
        if new_biggest > cur_biggest {
            biggest = new_biggest;
        }
        if biggest == number_of_messages {
            println!("No new messages");
            continue;
        }
        for message in biggest + 1..number_of_messages + 1 {
            let tmp_filename = format!("{}/tmp/{}", account.maildir, message);
            let filename = format!("{}/new/{}", account.maildir, message);
            {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&tmp_filename)?;
                file.write_all(&retr(&mut stream, message)?)?;
            }
            if Path::new(&filename).exists() {
                fs::remove_file(&filename)?;
            }
            fs::hard_link(&tmp_filename, &filename)?;
            fs::remove_file(&tmp_filename)?;
        }
        println!("QUIT");
        println!("{}", quit(&mut stream)?);
    }

    Ok(())
}
