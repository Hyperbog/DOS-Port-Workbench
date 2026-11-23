image 0000:0000 0008 21CD30B4
stack_words 7
start 0C7E:0B28 wipe_window_retf
watch 0B62:00A8 create_program_entry
watch 0B62:0044 create_helper
watch 0B62:0065 store_instance
watch 0B62:0071 send_create
watch 10F5:08F2 dispatch_create
watch 10F5:0911 lookup_instance
watch 10F5:0913 instance_loaded
watch 10F5:0991 match_create
watch 10F5:09D5 handler_header
watch 10F5:09DF first_opcode
watch 10F5:190E handler_end
watch 10F5:1921 handler_result
watch 10F5:192F handler_retf
watch 0B62:0076 dispatch_return
watch 0B62:011D load_slot_result
stop 0B62:0124 create_program_retf
