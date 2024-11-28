use n42_testing_util::{clique_test::{TesterVote, CliqueTest}, snapshot_test_utils};

#[test]
async fn main() {
    let tests = vec![
        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "B".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            }],
            results: vec!["A".to_string()],
            failure: None,
        },
        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "C".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
            ],
            results: vec!["A".to_string(),"B".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "B".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "B".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
            ],
            results: vec!["A".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },TesterVote{
                signer: "B".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
                        TesterVote{
                            signer: "A".to_string(),
                            voted: "D".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote{
                            signer: "B".to_string(),
                            voted: "D".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote{
                            signer: "A".to_string(),
                            voted: "E".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote{
                            signer: "B".to_string(),
                            voted: "E".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
            ],
            results: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
                        TesterVote {
                            signer: "A".to_string(),
                            voted: "C".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "A".to_string(),
                            voted: "C".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        }


            ],
            results: vec!["A".to_string(),"B".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },

                        TesterVote {
                            signer: "A".to_string(),
                            voted: "D".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },

                        TesterVote {
                            signer: "B".to_string(),
                            voted: "C".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "D".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        }

            ],
            results: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },

                        TesterVote {
                            signer: "A".to_string(),
                            voted: "C".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },

                        TesterVote {
                            signer: "A".to_string(),
                            voted: "C".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },


            ],
            results: vec!["A".to_string(),"B".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
                        TesterVote {
                            signer: "A".to_string(),
                            voted: "D".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "C".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "D".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "C".to_string(),
                            voted: "D".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "C".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },


            ],
            results: vec!["A".to_string(),"B".to_string(),"C".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
                        TesterVote {
                            signer: "A".to_string(),
                            voted: "D".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "C".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "D".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "C".to_string(),
                            voted: "D".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "C".to_string(),
                            voted: "C".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },


            ],
            results: vec!["A".to_string(),"B".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: false,
                checkpoint: vec![],
                newbatch: false,
            },
                        TesterVote {
                            signer: "A".to_string(),
                            voted: "D".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "C".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "D".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "C".to_string(),
                            voted: "D".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },


            ],
            results: vec!["A".to_string(),"B".to_string(),"C".to_string(),],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string(),"D".to_string(),"E".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "F".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "F".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "C".to_string(),
                            voted: "F".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "D".to_string(),
                            voted: "F".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "E".to_string(),
                            voted: "F".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "F".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "C".to_string(),
                            voted: "F".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "D".to_string(),
                            voted: "F".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "E".to_string(),
                            voted: "F".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "A".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "C".to_string(),
                            voted: "A".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "D".to_string(),
                            voted: "A".to_string(),
                            auth: false,
                            checkpoint: vec![],
                            newbatch: false,
                        },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "F".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
            ],
            results: vec!["B".to_string(),"C".to_string(),"D".to_string(),"E".to_string(),"F".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 3,
            signers: vec!["A".to_string(),"B".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "C".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            },
                        TesterVote {
                            signer: "B".to_string(),
                            voted: "C".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: false,
                        },
            ],
            results: vec!["A".to_string(),"B".to_string()],
            failure: None,
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "".to_string(),
                auth: true,
                checkpoint: vec![],
                newbatch: false,
            }],
            results: vec![],
            failure: Some("unauthorized signer".to_string()),
        },

        CliqueTest {
            epoch: 0,
            signers: vec!["A".to_string(),"B".to_string(),"C".to_string()],
            votes: vec![TesterVote {
                signer: "A".to_string(),
                voted: "".to_string(),
                auth: true,
                checkpoint: vec!["A".to_string(),"B".to_string(),"C".to_string()],
                newbatch: false,
            },
                        TesterVote {
                            signer: "A".to_string(),
                            voted: "".to_string(),
                            auth: true,
                            checkpoint: vec![],
                            newbatch: true,
                        }

            ],
            results: vec![],
            failure: Some("unauthorized signer".to_string()),
        },
        // Add more test cases here...
    ];

    for (i, test) in tests.iter().enumerate() {
        if let Err(e) = test.run().await {
            eprintln!("Test {} failed: {:?}", i, e);
        }
    }

    // // Run each test in the vector
    // for test in tests {
    //     test.run();
    // }

}
