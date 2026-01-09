use crate::gtp::{gtp::*, gtp_ie::*, gtpv2_types::*};
use crate::gtp_call_flow::*;

pub async fn make_mock_callflow()
-> Vec<CallFlow>
{
    let mut v = Vec::new();

    // ======================
    // LBI 5 : EBI 5
    // ======================

    v.push(CallFlow {
        id: 1,
        timestamp: String::new(),
        src_addr: "10.10.2.72".into(), // UE / MME
        dst_addr: "10.10.1.71".into(), // SGW
        message: "Create Session Request".into(),
        ebi: None,
        bearer: Some(vec![ Bearer {
            ebi: 5,
            fteid_list:None,
            }])
    });

    v.push(CallFlow {
        id: 2,
        timestamp: String::new(),
        src_addr: "10.10.1.71".into(),
        dst_addr: "10.10.3.73".into(), // PGW
        message: "Create Session Request".into(),
        ebi: None,
        bearer: Some(vec![ Bearer {
            ebi: 5,
            fteid_list: Some(vec![FTeidValue { 
                v4: true,
                v6: false,
                iface_type: 4, //S5S8 SGW
                teid: 123u32,
                ipv4: Some("10.10.1.71".into()),
                ipv6: None,
            }])
        }]),
    });

    v.push(CallFlow {
        id: 3,
        timestamp: String::new(),
        src_addr: "10.10.3.73".into(),
        dst_addr: "10.10.1.71".into(),
        message: "Create Session Response".into(),
        ebi: None,
        bearer: Some(vec![Bearer {
            ebi: 5,
            fteid_list: Some(vec![FTeidValue { 
                v4: true,
                v6: false,
                iface_type: 5, //S5S8 PGW
                teid: 321u32,
                ipv4: Some("10.10.3.73".into()),
                ipv6: None,
            }])
        }]),
    });

    v.push(CallFlow {
        id: 4,
        timestamp: String::new(),
        src_addr: "10.10.1.71".into(),
        dst_addr: "10.10.2.72".into(),
        message: "Create Session Response".into(),
        ebi: None,
        bearer: Some(vec![Bearer {
            ebi: 5,
            fteid_list: Some(vec![FTeidValue { 
                v4: true,
                v6: false,
                iface_type: 1, //S1-U Sgw
                teid: 132u32,
                ipv4: Some("10.10.1.71".into()),
                ipv6: None,
            }])
        }]),
    });

    // ---- Modify Bearer (EBI 6 추가)
    v.push(CallFlow {
        id: 5,
        timestamp: String::new(),
        src_addr: "10.10.2.72".into(),
        dst_addr: "10.10.1.71".into(),
        message: "Modify Bearer Request".into(),
        ebi: None,
        bearer: Some(vec![Bearer {
            ebi: 5,
            fteid_list: Some(vec![FTeidValue { 
                v4: true,
                v6: false,
                iface_type: 0, //S1-U eNB
                teid: 213u32,
                ipv4: Some("10.10.2.72".into()),
                ipv6: None,
            }])
        }]),
    });
    v.push(CallFlow {
        id: 6,
        timestamp: String::new(),
        src_addr: "10.10.1.71".into(),
        dst_addr: "10.10.2.72".into(),
        message: "Modify Bearer Response".into(),
        ebi: None,
        bearer: Some(vec![Bearer {
            ebi: 5,
            fteid_list: Some(vec![FTeidValue { 
                v4: true,
                v6: false,
                iface_type: 1, //S1-U SGW
                teid: 132u32,
                ipv4: Some("10.10.1.71".into()),
                ipv6: None,
            }])
        }]),
    });

    // ---- Create Bearer
    // ======================
    // LBI 5 : EBI 9, 10, 11
    // ======================

    v.push(CallFlow {
        id: 7,
        timestamp: String::new(),
        src_addr: "10.10.3.73".into(),
        dst_addr: "10.10.1.71".into(),
        message: "Create Bearer Request".into(),
        ebi: Some(5), //LBi
        bearer: Some(vec![
            Bearer {
                ebi: 0,
                fteid_list: Some(vec![
                    FTeidValue { 
                        v4: true,
                        v6: false,
                        iface_type: 5, //S5/S8 PGW
                        teid: 345u32,
                        ipv4: Some("10.10.3.73".into()),
                        ipv6: None,
                    }
                ])
            },
            Bearer {
                ebi: 0,
                fteid_list: Some(vec![
                    FTeidValue { 
                        v4: true,
                        v6: false,
                        iface_type: 5, //S5/S8 PGW
                        teid: 346u32,
                        ipv4: Some("10.10.3.73".into()),
                        ipv6: None,
                    }
                ])
            },
            Bearer {
                ebi: 0,
                fteid_list: Some(vec![
                    FTeidValue { 
                        v4: true,
                        v6: false,
                        iface_type: 5, //S5/S8 PGW
                        teid: 347u32,
                        ipv4: Some("10.10.3.73".into()),
                        ipv6: None,
                    }
                ])
            },
        ]),
    });

    v.push(CallFlow {
        id: 8,
        timestamp: String::new(),
        src_addr: "10.10.1.71".into(),
        dst_addr: "10.10.2.72".into(),
        message: "Create Bearer Request".into(),
        ebi: Some(5), //LBi
        bearer: Some(
            vec![
            Bearer {
                ebi: 0,
                fteid_list: Some(vec![
                    FTeidValue { 
                        v4: true,
                        v6: false,
                        iface_type: 5, //S5/S8 PGW
                        teid: 345u32,
                        ipv4: Some("10.10.3.73".into()),
                        ipv6: None,
                    },
                    FTeidValue { 
                        v4: true,
                        v6: false,
                        iface_type: 1, //S1-U SGW
                        teid: 145u32,
                        ipv4: Some("10.10.1.71".into()),
                        ipv6: None,
                }])
            },
            Bearer {
                ebi: 0,
                fteid_list: Some(vec![
                    FTeidValue { 
                        v4: true,
                        v6: false,
                        iface_type: 5, //S5/S8 PGW
                        teid: 346u32,
                        ipv4: Some("10.10.3.73".into()),
                        ipv6: None,
                    },
                    FTeidValue { 
                        v4: true,
                        v6: false,
                        iface_type: 1, //S1-U SGW
                        teid: 146u32,
                        ipv4: Some("10.10.1.71".into()),
                        ipv6: None,
                }])
            },
            Bearer {
                ebi: 0,
                fteid_list: Some(vec![
                    FTeidValue { 
                        v4: true,
                        v6: false,
                        iface_type: 5, //S5/S8 PGW
                        teid: 347u32,
                        ipv4: Some("10.10.3.73".into()),
                        ipv6: None,
                    },
                    FTeidValue { 
                        v4: true,
                        v6: false,
                        iface_type: 1, //S1-U SGW
                        teid: 147u32,
                        ipv4: Some("10.10.1.71".into()),
                        ipv6: None,
                }])
            },
            ]
        ),
    });

    v.push(CallFlow {
        id: 9,
        timestamp: String::new(),
        src_addr: "10.10.2.72".into(),
        dst_addr: "10.10.1.71".into(),
        message: "Create Bearer Response".into(),
        ebi: None, //LBi
        bearer: Some(
            vec![
                Bearer {
                    ebi: 9,
                    fteid_list: Some(vec![
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 0, //S1-U eNB
                            teid: 245u32,
                            ipv4: Some("10.10.2.72".into()),
                            ipv6: None,
                        },
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 1, //S1-U SGW
                            teid: 145u32,
                            ipv4: Some("10.10.1.71".into()),
                            ipv6: None,
                        }
                    ])
                },
                Bearer{
                    ebi: 10,
                    fteid_list: Some(vec![
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 0, //S1-U eNB
                            teid: 246u32,
                            ipv4: Some("10.10.2.72".into()),
                            ipv6: None,
                        },
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 1, //S1-U SGW
                            teid: 146u32,
                            ipv4: Some("10.10.1.71".into()),
                            ipv6: None,
                        }
                    ])
                },
                Bearer{
                    ebi: 11,
                    fteid_list: Some(vec![
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 0, //S1-U eNB
                            teid: 247u32,
                            ipv4: Some("10.10.2.72".into()),
                            ipv6: None,
                        },
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 1, //S1-U SGW
                            teid: 147u32,
                            ipv4: Some("10.10.1.71".into()),
                            ipv6: None,
                        }
                    ])
                }
            ]
        ),
    });

    v.push(CallFlow {
        id: 10,
        timestamp: String::new(),
        src_addr: "10.10.1.71".into(),
        dst_addr: "10.10.3.73".into(),
        message: "Create Bearer Response".into(),
        ebi: None, //LBi
        bearer: Some(
            vec![
                Bearer {
                    ebi: 9,
                    fteid_list: Some(vec![
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 4, //S5/S8 SGW
                            teid: 155u32,
                            ipv4: Some("10.10.1.71".into()),
                            ipv6: None,
                        },
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 5, //S5/S8 PGW
                            teid: 345u32,
                            ipv4: Some("10.10.3.73".into()),
                            ipv6: None,
                        }
                    ])
                },
                Bearer{
                    ebi: 10,
                    fteid_list: Some(vec![
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 4, //S5/S8 SGW
                            teid: 156u32,
                            ipv4: Some("10.10.1.71".into()),
                            ipv6: None,
                        },
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 5, //S5/S8 PGW
                            teid: 346u32,
                            ipv4: Some("10.10.3.73".into()),
                            ipv6: None,
                        }
                    ])
                },
                Bearer{
                    ebi: 11,
                    fteid_list: Some(vec![
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 4, //S5S8 SGW
                            teid: 157u32,
                            ipv4: Some("10.10.1.71".into()),
                            ipv6: None,
                        },
                        FTeidValue { 
                            v4: true,
                            v6: false,
                            iface_type: 5, //S5/S8 PGW
                            teid: 347u32,
                            ipv4: Some("10.10.3.73".into()),
                            ipv6: None,
                        }
                    ])
                }
            ]
        ),
    });


    // ---- Delete Bearer
    //====================
    //LBI: 5   EBI 9, 11 (10 will be removed)
    //====================
    v.push(CallFlow {
        id: 11,
        timestamp: String::new(),
        src_addr: "10.10.3.73".into(),
        dst_addr: "10.10.1.71".into(),
        message: "Delete Bearer Request".into(),
        ebi: Some(10),
        bearer: None,
    });

    v.push(CallFlow {
        id: 12,
        timestamp: String::new(),
        src_addr: "10.10.1.71".into(),
        dst_addr: "10.10.2.72".into(),
        message: "Delete Bearer Request".into(),
        ebi: Some(10),
        bearer: None,
      
    });

    v.push(CallFlow {
        id: 13,
        timestamp: String::new(),
        src_addr: "10.10.2.72".into(),
        dst_addr: "10.10.1.71".into(),
        message: "Delete Bearer Response".into(),
        ebi: None,
        bearer: Some (vec![
            Bearer {
                ebi: 10,
                fteid_list: None,
            }
        ])
    });
    v.push(CallFlow {
        id: 14,
        timestamp: String::new(),
        src_addr: "10.10.1.71".into(),
        dst_addr: "10.10.3.73".into(),
        message: "Delete Bearer Response".into(),
        ebi: None,
        bearer: Some (vec![
            Bearer {
                ebi: 10,
                fteid_list: None,
            }
        ])
    });

    // ---- Delete Session
    v.push(CallFlow {
        id: 15,
        timestamp: String::new(),
        src_addr: "10.10.2.72".into(),
        dst_addr: "10.10.1.71".into(),
        message: "Delete Session Request".into(),
        ebi: None,
        bearer: None,
    });

    v.push(CallFlow {
        id: 16,
        timestamp: String::new(),
        src_addr: "10.10.1.71".into(),
        dst_addr: "10.10.3.73".into(),
        message: "Delete Session Request".into(),
        ebi: None,
        bearer: None,
    });

    v.push(CallFlow {
        id: 17,
        timestamp: String::new(),
        src_addr: "10.10.3.73".into(),
        dst_addr: "10.10.1.71".into(),
        message: "Delete Session Response".into(),
        ebi: None,
        bearer: None,
    });

    v.push(CallFlow {
        id: 18,
        timestamp: String::new(),
        src_addr: "10.10.1.71".into(),
        dst_addr: "10.10.2.72".into(),
        message: "Delete Session Response".into(),
        ebi: None,
        bearer: None,
    });

    // ======================
    // LBI 7 : EBI 7, 8, 9
    // ======================

    // v.push(CallFlow {
    //     id: 20,
    //     timestamp: String::new(),
    //     src_addr: "10.10.2.80".into(),
    //     dst_addr: "10.10.1.71".into(),
    //     message: "Create Session Request".into(),
    //     ebi: None,
    //     bearer: None,
    // });

    // v.push(CallFlow {
    //     id: 21,
    //     timestamp: String::new(),
    //     src_addr: "10.10.1.71".into(),
    //     dst_addr: "10.10.3.73".into(),
    //     message: "Create Session Request".into(),
    //     ebi: None,
    //     bearer: Some(Bearer {
    //         ebi: 7,
    //         fteid_list: vec![FTeidValue { 
    //             v4: true,
    //             v6: false,
    //             iface_type: 0, //S1-U eNB
    //             teid: 0u32,
    //             ipv4: Some("10.10.1.71".into()),
    //             ipv6: None,
    //         }]
    //     }),
    // });

    // // ---- Modify Bearer (EBI 8, 9 추가)
    // v.push(CallFlow {
    //     id: 22,
    //     timestamp: String::new(),
    //     src_addr: "10.10.2.80".into(),
    //     dst_addr: "10.10.1.71".into(),
    //     message: "Modify Bearer Request".into(),
    //     ebi: None,
    //     bearer: Some(Bearer {
    //         ebi: 7,
    //         fteid_list: vec![FTeidValue { 
    //             v4: true,
    //             v6: false,
    //             iface_type: 0, //S1-U eNB
    //             teid: 0u32,
    //             ipv4: Some("10.10.2.80".into()),
    //             ipv6: None,
    //         }]
    //     }),
    // });

    // v.push(CallFlow {
    //     id: 23,
    //     timestamp: String::new(),
    //     src_addr: "10.10.1.71".into(),
    //     dst_addr: "10.10.2.80".into(),
    //     message: "Modify Bearer Response".into(),
    //     ebi: None,
    //     bearer: Some(Bearer {
    //         ebi: 7,
    //         fteid_list: vec![FTeidValue { 
    //             v4: true,
    //             v6: false,
    //             iface_type: 0, //S1-U eNB
    //             teid: 0u32,
    //             ipv4: Some("10.10.1.71".into()),
    //             ipv6: None,
    //         }]
    //     }),
    // });

    // // ---- Delete Session
    // v.push(CallFlow {
    //     id: 24,
    //     timestamp: String::new(),
    //     src_addr: "10.10.2.80".into(),
    //     dst_addr: "10.10.1.71".into(),
    //     message: "Delete Session Request".into(),
    //     ebi: None,
    //     bearer: None,
    // });

    // v.push(CallFlow {
    //     id: 25,
    //     timestamp: String::new(),
    //     src_addr: "10.10.1.71".into(),
    //     dst_addr: "10.10.2.80".into(),
    //     message: "Delete Session Response".into(),
    //     ebi: None,
    //     bearer: None,
    // });

    v
}