/// Define a tracepoint
///
/// User should call register_trace_\$name to register a callback function to the tracepoint and
/// call trace_\$name to trigger the callback function
#[macro_export]
macro_rules! define_trace_point {
    ($lock:ident,$name:ident,$($arg:ident:$arg_type:ty),*) => {
        paste::paste!{
            static_keys::define_static_key_false!([<__ $name _key>]);
            #[allow(non_upper_case_globals)]
            #[used]
            static [<__ $name>]: $lock<$crate::TracePoint> = $lock::new($crate::TracePoint::new(&[<__ $name _key>],stringify!($name), module_path!(),None,None));

            #[inline(always)]
            pub fn [<trace_ $name>]( $($arg:$arg_type),* ){

                if static_keys::static_branch_unlikely!([<__ $name _key>]){
                    let mut lock = [<__ $name>].lock();
                    let mut funcs = lock.callback_list();
                    for trace_func in funcs.values(){
                        let func = trace_func.func;
                        let data = trace_func.data.as_ref();
                        let func = unsafe{core::mem::transmute::<fn(),fn(& (dyn core::any::Any+Send+Sync),$($arg_type),*)>(func)};
                        func(data $(,$arg)*);
                    }
                }

            }

            pub fn [<register_trace_ $name>](func:fn(& (dyn core::any::Any+Send+Sync),$($arg_type),*),data:alloc::boxed::Box<dyn core::any::Any+Send+Sync>){
                let func = unsafe{core::mem::transmute::<fn(& (dyn core::any::Any+Send+Sync),$($arg_type),*),fn()>(func)};
                [<__ $name>].lock().register(func,data);
            }

            pub fn [<unregister_trace_ $name>](func:fn(& (dyn core::any::Any+Send+Sync),$($arg_type),*)){
                let func = unsafe{core::mem::transmute::<fn(& (dyn core::any::Any+Send+Sync),$($arg_type),*),fn()>(func)};
                [<__ $name>].lock().unregister(func);
            }

        }
    };
}

#[macro_export]
macro_rules! define_event_trace{
    ($name:ident,
        ($($arg:ident:$arg_type:ty),*),
        $fmt:expr) =>{
        define_trace_point!($name,$($arg:$arg_type),*);
        paste::paste!{
            #[derive(Debug)]
            #[repr(C)]
            #[allow(non_snake_case)]

            struct [<__ $name _TracePointMeta>]{
                trace_point: &'static $crate::TracePoint,
                print_func: fn(&mut (dyn core::any::Any+Send+Sync),$($arg_type),*),
            }
             #[allow(non_upper_case_globals)]
             #[link_section = ".tracepoint"]
             #[used]
            static [<__ $name _meta>]: [<__ $name _TracePointMeta>] = [<__ $name _TracePointMeta>]{
                trace_point:&[<__ $name>],
                print_func:[<trace_print_ $name>],
            };
            pub fn [<trace_print_ $name>](_data:&mut (dyn core::any::Any+Send+Sync),$($arg:$arg_type),* ){
                //  let time = $crate::time::Instant::now();
                //  let cpu_id = $crate::arch::cpu::current_cpu_id().data();
                //  let current_pid = $crate::process::ProcessManager::current_pcb().pid().data();
                //  let format = format!("[{}][{}][{}] {}\n",time,cpu_id,current_pid,$fmt);
                //  $crate::debug::tracing::trace_pipe::trace_pipe_push_record(format);
            }
        }
    };
}
