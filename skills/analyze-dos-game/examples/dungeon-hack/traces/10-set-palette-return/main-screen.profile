image 0000:0000 0008 21CD30B4
stack_words 7
start 0C7E:04F9 set_palette_entry stack5=001A
watch 0C7E:0516 palette_lookup
watch 0C7E:051B palette_resource
watch 12FC:2B25 first_color stack2=0000
watch 12FC:2B25 last_color stack2=00FF
watch 0C7E:064F colors_done
watch 0C7E:0914 final_rgb_distance stack8=001E
watch 0C7E:0926 release_call
watch 06BF:19C5 release_entry stack0=092B
watch 06BF:19E0 release_decrement stack3=092B
watch 06BF:19E7 release_retf stack0=092B
watch 0C7E:092B release_return
watch 0C7E:0931 set_palette_retf
watch 10F5:0E42 vm_resume
watch 10F5:0E4F store_low
watch 10F5:0E52 store_high
watch 10F5:0E56 result_stored
watch 10F5:0E5B release_arguments
watch 10F5:0E66 fetch_import
watch 10F5:0DBF import_operand
watch 10F5:0DD0 replace_low
watch 10F5:0DD7 import_stored
watch 10F5:0DE0 fetch_after_import
watch 10F5:0A87 fetch_constant
watch 10F5:0D89 fetch_after_short
watch 10F5:0AF2 negate_slot
watch 10F5:0AF8 fetch_after_negate
watch 10F5:0DA0 fetch_after_word
watch 10F5:0DEA call_argc
watch 10F5:0E00 marshal_last
watch 10F5:0E0D marshal_first
watch 10F5:0E3F far_call
stop 0B62:00A8 create_program_entry
