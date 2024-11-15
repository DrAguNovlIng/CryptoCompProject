use cc::{Alice, Bob, Group};

fn main() {
    // This main method runs the tests from the week-3-tests.rs file, it can also be run using the command `cargo test`
    // For the implementation of the structs and methods, check the lib.rs file
    // First bit indicates A, second bit B, last bit +/-
    // Example: 001 = O+, 110 = AB-
    // Truth table goes: 000  001  010  011  100  101  110  111 (left to right, and up to down)
    let true_truth_table: [[u8; 8]; 8] = [
        [1, 0, 0, 0, 0, 0, 0, 0],
        [1, 1, 0, 0, 0, 0, 0, 0],
        [1, 0, 1, 0, 0, 0, 0, 0],
        [1, 1, 1, 1, 0, 0, 0, 0],
        [1, 0, 0, 0, 1, 0, 0, 0],
        [1, 1, 0, 0, 1, 1, 0, 0],
        [1, 0, 1, 0, 1, 0, 1, 0],
        [1, 1, 1, 1, 1, 1, 1, 1],
    ];

    //Calculated truth table by the protocol, this was used for debugging and is used to check correctness
    let mut calculated_truth_table: [[u8; 8]; 8] = [
        [2, 2, 2, 2, 2, 2, 2, 2],
        [2, 2, 2, 2, 2, 2, 2, 2],
        [2, 2, 2, 2, 2, 2, 2, 2],
        [2, 2, 2, 2, 2, 2, 2, 2],
        [2, 2, 2, 2, 2, 2, 2, 2],
        [2, 2, 2, 2, 2, 2, 2, 2],
        [2, 2, 2, 2, 2, 2, 2, 2],
        [2, 2, 2, 2, 2, 2, 2, 2],
    ];

    // To save time, we have already generated a (safe-prime) group and saved it in a file
    // To create a new group, uncomment the line below:
    Group::new(512).write_group_to_file("group512new.txt");
    let common_group = Group::new_from_file("group512new.txt");

    // Tests for every combination of inputs, using the implementation example presented in the assignment exercise
    
    for i in 0..8 {
        for j in 0..8 {
            let mut alice = Alice::new(common_group.clone());
            let mut bob = Bob::new(common_group.clone());

            //m1 and m2 are the tuples for the different options in OT that Alice chooses between
            let m1 = alice.choose(i);
            let m2 = bob.transfer(j,m1);
            let z = alice.retrieve(m2);
            calculated_truth_table[i as usize][j as usize] = z;
        }
    }

    for i in 0..8 {
        for j in 0..8 {
            assert_eq!(
                calculated_truth_table[i as usize][j as usize],
                true_truth_table[i as usize][j as usize]
            );
        }
    }
 
    println!("All tests passed successfully!")
}
