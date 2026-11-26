//! `mesh-fx serve` as a process (PLAN-voice-quality Task 2).

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "../src/proto.rs"]
#[allow(dead_code)]
mod proto;

fn serve() -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_mesh-fx"))
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
}

fn exit_within(child: &mut std::process::Child, within: Duration) -> Option<i32> {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("still running after {within:?}");
}

#[test]
fn frames_come_back_in_order() {
    let mut child = serve();
    let (mut to, mut from) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
    for seq in 0..100u32 {
        let pcm = vec![seq as i16; proto::FRAME];
        proto::write(&mut to, &proto::Msg::Audio(seq, pcm.clone())).unwrap();
        assert_eq!(
            proto::read(&mut from).unwrap(),
            Some(proto::Msg::Audio(seq, pcm))
        );
    }
    drop(to);
    assert_eq!(
        exit_within(&mut child, Duration::from_secs(2)),
        Some(0),
        "clean end"
    );
}

#[test]
fn malformed_input_ends_it_cleanly() {
    let mut child = serve();
    let mut to = child.stdin.take().unwrap();
    to.write_all(&[42, 1, 0, 0, 0, 0]).unwrap();
    to.flush().unwrap();
    assert_eq!(exit_within(&mut child, Duration::from_secs(2)), Some(2));
}
