image 0000:0000 0008 21CD30B4
stack_words 7
start 0B62:00A8 next_create_program_entry stack3=07D3
watch 0B62:0065 store_instance
watch 0B62:0071 send_create
watch 10F5:08F2 tables_dispatch stack2=07D3
watch 10F5:0913 tables_instance stack1=07D3
watch 10F5:097A lookup_miss
watch 10F5:09ED miss_retf
watch 0B62:0076 create_return
watch 0B62:011D load_slot
watch 0B62:0124 tables_retf
watch 10F5:0E42 vm_resume
watch 10F5:0E4F store_low
watch 10F5:0E52 store_high
watch 10F5:0E56 result_stored
watch 10F5:0E66 fetch_law
watch 10F5:10E1 auto_base
watch 10F5:10E6 read_this
watch 10F5:10EA store_this
watch 10F5:10F3 fetch_send
watch 10F5:0E70 send_operands
watch 10F5:0ED8 send_zero_args
watch 10F5:0EEB call_dispatcher
watch 10F5:08F2 main_dispatch stack2=07D0
watch 10F5:0991 matched_message
watch 10F5:09D5 handler_frame
stop 10F5:09DF first_opcode
