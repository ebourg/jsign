/**
 * Copyright 2012 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http:/**www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.jsign.pe;

/**
 * Types of structures pointed in the "RVA &amp; Sizes" table (data directory).
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public enum DataDirectoryType {

    /** The export table */
    EXPORT_TABLE,               

    /** The import table */
    IMPORT_TABLE,               

    /** The resource table */
    RESOURCE_TABLE,             

    /** The exception table */
    EXCEPTION_TABLE,            

    /** The attribute certificate table */
    CERTIFICATE_TABLE,          

    /** The base relocation table */
    BASE_RELOCATION_TABLE,      

    /** The debug data starting */
    DEBUG,                      

    /** Reserved, must be 0 */
    ARCHITECTURE,               

    /** The RVA of the value to be stored in the global pointer register. The size member of this structure must be set to zero. */
    GLOBAL_POINTER,             

    /** The thread local storage (TLS) table */
    THREAD_LOCAL_STORAGE_TABLE, 

    /** The load configuration table */
    LOAD_CONFIG_TABLE,          

    /** The bound import table  */
    BOUND_IMPORT_TABLE,         

    /** The import address table */
    IMPORT_ADDRESS_TABLE,       

    /** The delay import descriptor */
    DELAY_LOAD_IMPORT_TABLE,    

    /** The CLR runtime header */
    CLR_RUNTIME_HEADER          
}
