



fn handle_file_event( data: &[u8]) {
    let mut event = FileEvent::default();
    plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
    let x = convert_result_to_string(&event.filename);
    let mut mode = "";

    match event.operation{
        1=>{
            mode = "Open";
        }
        _=>{
            mode = "idk";
        }
       

    }
    if !(x == ""){
        println!("Event PID:{},\n FNAME:{:?},\n OPERATION: {}\n", 
    event.pid,  x,mode,);

    }
}




fn convert_result_to_string(x: &[u8]) -> String {
    let mut output = String::new();

    for i in 0..x.len(){
        if x[i] == 0 {
        break;
    }
        output.push_str(&format!("{}", x[i] as char));

    }


    return output;
}
