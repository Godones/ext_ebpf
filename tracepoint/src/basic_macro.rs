/// Define a tracepoint
///
/// User should call register_trace_\$name to register a callback function to the tracepoint and
/// call trace_\$name to trigger the callback function
#[macro_export]
macro_rules! define_trace_point {
    ($lock:ident,$name:ident $(,$arg:ident:$arg_type:ty)*) => {
        paste!{
            static_keys::define_static_key_false!([<__ $name _KEY>]);
            #[allow(non_upper_case_globals)]
            #[used]
            static [<__ $name>]: $lock<$crate::TracePoint> = $lock::new($crate::TracePoint::new(&[<__ $name _KEY>],stringify!($name), module_path!(),None,None));

            #[inline(always)]
            #[allow(non_snake_case)]
            pub fn [<trace_ $name>]( $($arg:$arg_type),* ){

                if static_keys::static_branch_unlikely!([<__ $name _KEY>]){
                    let mut lock = [<__ $name>].lock();
                    let mut funcs = lock.callback_list();
                    for trace_func in funcs{
                        let func = trace_func.func;
                        let data = trace_func.data.as_ref();
                        let func = unsafe{core::mem::transmute::<fn(),fn(& (dyn core::any::Any+Send+Sync), $($arg_type),*)>(func)};
                        func(data $(,$arg)*);
                    }
                }
            }
            #[allow(non_snake_case)]
            pub fn [<register_trace_ $name>](func: fn(& (dyn core::any::Any+Send+Sync), $($arg_type),*), data: alloc::boxed::Box<dyn core::any::Any+Send+Sync>){
                let func = unsafe{core::mem::transmute::<fn(& (dyn core::any::Any+Send+Sync), $($arg_type),*), fn()>(func)};
                [<__ $name>].lock().register(func,data);
            }
            #[allow(non_snake_case)]
            pub fn [<unregister_trace_ $name>](func: fn(& (dyn core::any::Any+Send+Sync), $($arg_type),*)){
                let func = unsafe{core::mem::transmute::<fn(& (dyn core::any::Any+Send+Sync), $($arg_type),*), fn()>(func)};
                [<__ $name>].lock().unregister(func);
            }

        }
    };
}

#[macro_export]
macro_rules! define_event_trace{
    ($lock:ident,$kops:ident, $name:ident,
        ($($arg:ident:$arg_type:ty),*),
        $fmt:expr) =>{
        define_trace_point!($lock,$name $(,$arg:$arg_type)*);
        paste!{
            #[derive(Debug)]
            #[repr(C)]
            #[allow(non_snake_case,non_camel_case_types)]
            struct [<__ $name _TracePointMeta>]{
                trace_point: &'static $lock<$crate::TracePoint>,
                print_func: fn(&mut (dyn core::any::Any+Send+Sync), $($arg_type),*),
            }
            #[allow(non_upper_case_globals)]
            #[link_section = ".tracepoint"]
            #[used]
            static [<__ $name _meta>]: [<__ $name _TracePointMeta>] = [<__ $name _TracePointMeta>]{
                trace_point:& [<__ $name>],
                print_func:[<trace_print_ $name>]::<$kops>,
            };
            #[allow(non_snake_case)]
            pub fn [<trace_print_ $name>]<F:$crate::KernelTraceOps>(_data:&mut (dyn core::any::Any+Send+Sync), $($arg:$arg_type),* ){
                let time = F::time_now();
                let cpu_id = F::cpu_id();
                let current_pid = F::current_pid();
                let format = format!("[{}][{}][{}] {}\n",time,cpu_id,current_pid,$fmt);
                F::trace_pipe_push_record(format);
            }
        }
    };
}
