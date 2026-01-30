mod e2e;

use e2e::{executor::SystemUnderTest, state_machine::OperatorStateMachine, TestFixture};
use proptest::prelude::*;
use proptest_state_machine::{prop_state_machine, ReferenceStateMachine, StateMachineTest};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

prop_state_machine! {
    #![proptest_config(ProptestConfig {
        cases: 10,
        max_shrink_iters: 50,
        // Note: timeout implies fork, so don't set it - we handle our own timeouts
        fork: false,  // Must disable fork - shared K3s container doesn't work across processes
        ..Default::default()
    })]

    #[test]
    fn operator_reconciliation(sequential 1..8 => OperatorStateMachine);
}

impl StateMachineTest for OperatorStateMachine {
    type SystemUnderTest = SystemUnderTest;
    type Reference = OperatorStateMachine;

    fn init_test(
        _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) -> Self::SystemUnderTest {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let subscriber = FmtSubscriber::builder()
                .with_max_level(Level::INFO)
                .with_test_writer()
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        });

        let rt = get_or_create_runtime();

        let fixture = rt.block_on(async {
            TestFixture::get_or_init().await
        });

        rt.block_on(async {
            fixture.cleanup().await.expect("cleanup failed");
        });

        SystemUnderTest::new(fixture)
    }

    fn apply(
        mut state: Self::SystemUnderTest,
        ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        transition: <Self::Reference as ReferenceStateMachine>::Transition,
    ) -> Self::SystemUnderTest {
        let rt = get_or_create_runtime();

        rt.block_on(async {
            info!("Applying transition: {:?}", transition);
            state.apply(&transition, ref_state).await.expect("transition failed");

            let new_ref = <OperatorStateMachine as ReferenceStateMachine>::apply(ref_state.clone(), &transition);
            state.verify(&new_ref).await.expect("verification failed");
        });

        state
    }

    fn check_invariants(
        state: &Self::SystemUnderTest,
        ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) {
        let rt = get_or_create_runtime();

        rt.block_on(async {
            state.verify(ref_state).await.expect("invariant check failed");
        });
    }
}

fn get_or_create_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Runtime::new().expect("Failed to create runtime")
    })
}
