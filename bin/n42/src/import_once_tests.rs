// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The registry on its own: who works, who waits, what each is told.

use super::*;

fn hash(n: u8) -> B256 {
    B256::repeat_byte(n)
}

fn owner(claim: Claim) -> Owner {
    match claim {
        Claim::Owner(owner) => owner,
        Claim::Waiter(_) => panic!("expected the owner"),
    }
}

fn waiter(claim: Claim) -> Waiter {
    match claim {
        Claim::Waiter(waiter) => waiter,
        Claim::Owner(_) => panic!("expected a waiter"),
    }
}

async fn next(waiter: &mut Waiter) -> Event {
    tokio::time::timeout(std::time::Duration::from_secs(5), waiter.next()).await.expect("an event within 5 s")
}

/// k requests for one hash: one owner, k-1 waiters; every waiter hears the
/// check, then the final status, and only one import is counted.
#[tokio::test]
async fn k_requests_import_once_and_all_hear_checked_then_the_status() {
    let registry = Arc::new(Registry::new(DEFAULT_CAP));
    let first = owner(registry.claim(hash(1)));
    let mut waiters: Vec<Waiter> = (0..6).map(|_| waiter(registry.claim(hash(1)))).collect();
    let tasks: Vec<_> = waiters
        .drain(..)
        .map(|mut waiter| {
            tokio::spawn(async move {
                let checked = matches!(next(&mut waiter).await, Event::Checked);
                let done = match next(&mut waiter).await {
                    Event::Done(status) => status,
                    other => panic!("expected the status, got {other:?}"),
                };
                (checked, done)
            })
        })
        .collect();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    first.checked();
    // The execution between the check and the status.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    first.done(vec![7, 7, 7], true);
    for task in tasks {
        let (checked, done) = task.await.expect("waiter");
        assert!(checked, "CHECKED before the status");
        assert_eq!(done.as_slice(), &[7, 7, 7]);
    }
    let counts = first.counts();
    assert_eq!((counts.requests, counts.served, counts.imports, counts.blocks), (7, 6, 1, 1));
    assert_eq!(counts.takeovers, 0);
}

/// A request arriving after the status is answered at once, from the
/// registry, and does nothing.
#[tokio::test]
async fn a_request_after_completion_is_answered_from_the_registry() {
    let registry = Arc::new(Registry::new(DEFAULT_CAP));
    let first = owner(registry.claim(hash(2)));
    first.checked();
    first.done(vec![1, 2], true);
    drop(first);
    let mut late = waiter(registry.claim(hash(2)));
    match next(&mut late).await {
        Event::Done(status) => assert_eq!(status.as_slice(), &[1, 2]),
        other => panic!("expected the status, got {other:?}"),
    }
    assert_eq!(late.registry.counts(&late.cell).imports, 1, "no second import");
}

/// The owner dies before it has a status: one waiter takes the work over, the
/// others wait for that one, and a waiter that already heard the check is not
/// told it twice.
#[tokio::test]
async fn the_first_requester_dying_hands_the_work_over() {
    let registry = Arc::new(Registry::new(DEFAULT_CAP));
    let first = owner(registry.claim(hash(3)));
    let mut a = waiter(registry.claim(hash(3)));
    let mut b = waiter(registry.claim(hash(3)));
    first.checked();
    assert!(matches!(next(&mut a).await, Event::Checked));
    assert!(matches!(next(&mut b).await, Event::Checked));
    drop(first);
    let second = match next(&mut a).await {
        Event::TakeOver(owner) => owner,
        other => panic!("a takes over, got {other:?}"),
    };
    // b sees a vacant cell that a has already claimed: it keeps waiting.
    let b_task = tokio::spawn(async move {
        match next(&mut b).await {
            Event::Done(status) => status,
            other => panic!("b waits for a's status, got {other:?}"),
        }
    });
    tokio::task::yield_now().await;
    second.checked();
    second.done(vec![9], true);
    assert_eq!(b_task.await.expect("b").as_slice(), &[9]);
    let counts = second.counts();
    assert_eq!((counts.imports, counts.takeovers, counts.blocks), (2, 1, 1));
}

/// A status that may change answers the waiters of the moment and nobody
/// after them: the next request does the work again.
#[tokio::test]
async fn a_status_that_may_change_is_not_kept_for_later_requests() {
    let registry = Arc::new(Registry::new(DEFAULT_CAP));
    let first = owner(registry.claim(hash(4)));
    let mut now = waiter(registry.claim(hash(4)));
    first.done(vec![5], false);
    assert!(matches!(next(&mut now).await, Event::Done(_)));
    drop(first);
    let later = owner(registry.claim(hash(4)));
    assert_eq!(later.counts().imports, 2);
}

/// Different hashes never wait on each other.
#[tokio::test]
async fn different_hashes_are_independent() {
    let registry = Arc::new(Registry::new(DEFAULT_CAP));
    let _a = owner(registry.claim(hash(5)));
    let _b = owner(registry.claim(hash(6)));
    assert_eq!(registry.len(), 2);
}

/// The registry keeps `cap` hashes: finished ones leave first, one still
/// being worked on stays until twice the cap.
#[test]
fn the_registry_is_bounded() {
    let registry = Arc::new(Registry::new(4));
    for n in 0..20u8 {
        let owner = owner(registry.claim(hash(100 + n)));
        owner.done(vec![n], true);
    }
    assert!(registry.len() <= 4, "finished entries leave: {}", registry.len());

    let registry = Arc::new(Registry::new(4));
    let working: Vec<Owner> = (0..8u8).map(|n| owner(registry.claim(hash(200 + n)))).collect();
    assert_eq!(registry.len(), 8, "working entries stay up to twice the cap");
    let _more = owner(registry.claim(hash(250)));
    assert!(registry.len() <= 8, "past twice the cap the oldest goes: {}", registry.len());
    // An evicted cell still works for whoever holds it.
    working[0].done(vec![1], true);
}

/// A single requester -- one validator per execution layer -- owns every
/// block, waits on nothing and is never answered from the registry.
#[test]
fn a_single_requester_always_owns() {
    let registry = Arc::new(Registry::new(DEFAULT_CAP));
    for n in 0..10u8 {
        let owner = owner(registry.claim(hash(n)));
        owner.checked();
        owner.done(vec![n], true);
        let counts = owner.counts();
        assert_eq!((counts.requests, counts.served), (1, 0));
    }
}

/// Off unless asked for; the held-execution combination is refused.
#[test]
fn off_by_default_and_the_held_combination_is_refused() {
    if std::env::var_os("N42_IMPORT_ONCE").is_none() {
        assert!(!enabled());
        assert!(global().is_none());
    }
    assert!(refuse_held(true, true).is_err(), "import-once with held executions is refused");
    assert!(refuse_held(true, false).is_ok());
    assert!(refuse_held(false, true).is_ok());
}
