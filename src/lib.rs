use core::slice;
use p256::elliptic_curve::sec1::ToEncodedPoint;

#[no_mangle]
pub extern "C" fn private_to_public_key(input: *const u8, output: *mut u8) 
{
    let private_key_bytes = unsafe { slice::from_raw_parts(input, 32) };
    let secret_key = p256::SecretKey::from_slice(private_key_bytes).unwrap();

    let binding = secret_key.public_key().to_encoded_point(true);
    let public_key = binding.as_bytes();
    unsafe {
        output.copy_from(public_key.as_ptr(), public_key.len());
    }
}