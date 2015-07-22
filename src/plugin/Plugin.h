// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PLUGIN_PLUGIN_H
#define PLUGIN_PLUGIN_H

#include <list>
#include <string>
#include <utility>

#include "config.h"
#include "analyzer/Component.h"
#include "file_analysis/Component.h"
#include "iosource/Component.h"

// We allow to override this externally for testing purposes.
#ifndef BRO_PLUGIN_API_VERSION
#define BRO_PLUGIN_API_VERSION 3
#endif

class ODesc;
class Func;
class Event;

namespace plugin  {

class Manager;
class Component;
class Plugin;

/**
 * Hook types that a plugin may define. Each label maps to the corresponding
 * virtual method in \a Plugin.
 */
enum HookType {
	// Note: when changing this table, update hook_name() in Plugin.cc.
	HOOK_LOAD_FILE,			//< Activates Plugin::HookLoadFile().
	HOOK_CALL_FUNCTION,		//< Activates Plugin::HookCallFunction().
	HOOK_QUEUE_EVENT,		//< Activates Plugin::HookQueueEvent().
	HOOK_DRAIN_EVENTS,		//< Activates Plugin::HookDrainEvents()
	HOOK_UPDATE_NETWORK_TIME,	//< Activates Plugin::HookUpdateNetworkTime.
	HOOK_BRO_OBJ_DTOR,		//< Activates Plugin::HookBroObjDtor.

	// Meta hooks.
	META_HOOK_PRE,			//< Activates Plugin::MetaHookPre().
	META_HOOK_POST,			//< Activates Plugin::MetaHookPost().

	// End marker.
	NUM_HOOKS,
};

/**
 * Converts a hook type into a readable hook name.
 */
extern const char* hook_name(HookType h);

/**
 * Helper class to capture a plugin's version.
 * */
struct VersionNumber {
	int major; //< Major version number;
	int minor; //< Minor version number;

	/**
	 *  Constructor.
	 */
	VersionNumber()	{ major = minor = -1; }

	/**
	 *  Returns true if the version is set to a non-negative value.
	 */
	operator bool() const { return major >= 0 && minor >= 0; }
};

/**
 * A class defining a plugin's static configuration parameters.
 */
class Configuration {
public:
	std::string name;		//< The plugin's name, including a namespace. Mandatory.
	std::string description;	//< A short textual description of the plugin. Mandatory.
	VersionNumber version;		//< THe plugin's version. Optional.

	// We force this to inline so that the API version gets hardcoded
	// into the external plugin. (Technically, it's not a "force", just a
	// strong hint.). The attribute seems generally available.
	inline Configuration() __attribute__((always_inline));

private:
	friend class Plugin;
	int api_version;	// Current BRO_PLUGIN_API_VERSION. Automatically set.
};

inline Configuration::Configuration()
		{
		name = "";
		description = "";
		api_version = BRO_PLUGIN_API_VERSION;
		}

/**
 * A class describing an item defined in \c *.bif file.
 */
class BifItem {
public:
	/**
	 * Type of the item.
	 */
	enum Type { FUNCTION = 1, EVENT = 2, CONSTANT = 3, GLOBAL = 4, TYPE = 5 };

	/**
	 * Constructor.
	 *
	 * @param id The script-level name of the item. This should be fully
	 * qualified.
	 *
	 * @param type The type of the item.
	 */
	BifItem(const std::string& id, Type type);

	/**
	 * Copy constructor.
	 */
	BifItem(const BifItem& other);

	/**
	 * Assigment operator.
	 */
	BifItem& operator=(const BifItem& other);

	/**
	 * Destructor.
	 */
	~BifItem();

	/**
	 * Returns the script-level ID as passed into the constructor.
	 */
	const std::string& GetID() const	{ return id; }

	/**
	 * Returns the type as passed into the constructor.
	 */
	Type GetType() const	{ return type; }

private:
	std::string id;
	Type type;
};

/**
 * A class encapsulating an event argument to then pass along with a meta hook.
 */
class HookArgument
{
public:
	/**
	 * Type of the argument.
	 */
	enum Type {
		BOOL, DOUBLE, EVENT, FRAME, FUNC, FUNC_RESULT, INT, STRING, VAL, VAL_LIST, VOID, VOIDP
	};

	/**
	 * Default constructor initialized the argument with type VOID.
	 */
	HookArgument()	{ type = VOID; }

	/**
	 * Constructor with a boolean argument.
	 */
	HookArgument(bool a)	{ type = BOOL; arg.bool_ = a; }

	/**
	 * Constructor with a double argument.
	 */
	HookArgument(double a)	{ type = DOUBLE; arg.double_ = a; }

	/**
	 * Constructor with an event argument.
	 */
	HookArgument(const Event* a)	{ type = EVENT; arg.event = a; }

	/**
	 * Constructor with a function argument.
	 */
	HookArgument(const Func* a)	{ type = FUNC; arg.func = a; }

	/**
	 * Constructor with an integer  argument.
	 */
	HookArgument(int a)	{ type = INT; arg.int_ = a; }

	/**
	 * Constructor with a string argument.
	 */
	HookArgument(const std::string& a)	{ type = STRING; arg_string = a; }

	/**
	 * Constructor with a Bro value argument.
	 */
	HookArgument(const Val* a)	{ type = VAL; arg.val = a; }

	/**
	 * Constructor with a list of Bro values argument.
	 */
	HookArgument(const val_list* a)	{ type = VAL_LIST; arg.vals = a; }

	/**
	 * Constructor with a void pointer argument.
	 */
	HookArgument(void* p)	{ type = VOIDP; arg.voidp = p; }

	/**
	 * Constructor with a function result argument.
	 */
	HookArgument(std::pair<bool, Val*> fresult)	{ type = FUNC_RESULT; func_result = fresult; }

	/**
	 * Constructor with a Frame argument.
	 */
	HookArgument(Frame* f)	{ type = FRAME; arg.frame = f; }

	/**
	 * Returns the value for a boolen argument. The argument's type must
	 * match accordingly.
	 */
	bool AsBool() const	{ assert(type == BOOL); return arg.bool_; }

	/**
	 * Returns the value for a double argument. The argument's type must
	 * match accordingly.
	 */
	double AsDouble() const	{ assert(type == DOUBLE); return arg.double_; }

	/**
	 * Returns the value for an event argument. The argument's type must
	 * match accordingly.
	 */
	const Event* AsEvent() const	{ assert(type == EVENT); return arg.event; }

	/**
	 * Returns the value for a function argument. The argument's type must
	 * match accordingly.
	 */
	const Func* AsFunc() const	{ assert(type == FUNC); return arg.func; }

	/**
	 * Returns the value for an integer argument. The argument's type must
	 * match accordingly.
	 */
	double AsInt() const	{ assert(type == INT); return arg.int_; }

	/**
	 * Returns the value for a string argument. The argument's type must
	 * match accordingly.
	 */
	const std::string& AsString() const	{ assert(type == STRING); return arg_string; }

	/**
	 * Returns the value for a Bro value argument. The argument's type must
	 * match accordingly.
	 */
	const Val* AsVal() const	{ assert(type == VAL); return arg.val; }

	/**
	 * Returns the value for a Bro wrapped value argument.  The argument's type must
	 * match accordingly.
	 */
	const std::pair<bool, Val*> AsFuncResult() const { assert(type == FUNC_RESULT); return func_result; }

	/**
	 * Returns the value for a Bro frame argument.  The argument's type must
	 * match accordingly.
	 */
	const Frame* AsFrame() const { assert(type == FRAME); return arg.frame; }

	/**
	 * Returns the value for a list of Bro values argument. The argument's type must
	 * match accordingly.
	 */
	const val_list* AsValList() const	{ assert(type == VAL_LIST); return arg.vals; }

	/**
	 * Returns the value for a vod pointer argument. The argument's type
	 * must match accordingly.
	 */
	const void* AsVoidPtr() const	{ assert(type == VOIDP); return arg.voidp; }

	/**
	 * Returns the argument's type.
	 */
	Type GetType() const	{ return type; }

	/**
	 * Returns a textual representation of the argument.
	 *
	 * @param d Description object to use for rendering.
	 */
	void Describe(ODesc* d) const;

private:
	Type type;
	union {
		bool bool_;
		double double_;
		const Event* event;
		const Func* func;
		const Frame* frame;
		int int_;
		const Val* val;
		const val_list* vals;
		const void* voidp;
	} arg;

	// Outside union because these have dtors.
	std::pair<bool, Val*> func_result;
	std::string arg_string;
};

typedef std::list<HookArgument> HookArgumentList;

/**
 * Base class for all plugins.
 *
 * Plugins encapsulate functionality that extends one or more of Bro's major
 * subsystems, such as analysis of a specific protocol, or logging output in
 * a particular format. A plugin acts a logical container that can provide a
 * set of functionality. Specifically, it may:
 *
 * - Provide one or more \a components implementing functionality. For
 *   example, a RPC plugin could provide analyzer for set of related
 *   protocols (RPC, NFS, etc.), each of which would be a separate component.
 *   Likewise, an SQLite plugin could provide both a writer and reader
 *   component.
 *
 * - Provide BiF elements (functions, events, types, globals). Typically
 *   they'll be defined in *.bif files, but a plugin can also create them
 *   internally.
 *
 * - Provide hooks (aka callbacks) into Bro's core processing to inject
 *   and/or alter functionality.
 *
 * A plugin needs to explicitly register all the functionality it provides.
 * For components, it needs to call AddComponent(); for BiFs AddBifItem();
 * and for hooks EnableHook() and then also implement the corresponding
 * virtual methods.
 *
 */
class Plugin {
public:
	typedef std::list<Component *> component_list;
	typedef std::list<BifItem> bif_item_list;
	typedef std::list<std::pair<HookType, int> > hook_list;

	/**
	 * Constructor.
	 */
	Plugin();

	/**
	 * Destructor.
	 */
	virtual ~Plugin();

	/**
	 * Returns the name of the plugin.
	 */
	const std::string& Name() const;

	/**
	 * Returns a short textual description of the plugin, if provided.
	 */
	const std::string& Description() const;

	/**
	 * Returns the version of the plugin. Versions are only meaningful
	 * for dynamically compiled plugins; for statically compiled ones,
	 * this will always return 0.
	 */
	VersionNumber Version() const;

	/**
	 * Returns true if this is a dynamically linked plugin.
	 */
	bool DynamicPlugin() const;

	/**
	 * For dynamic plugins, returns the base directory from which it was
	 * loaded. For static plugins, returns an empty string.
	 **/
	const std::string& PluginDirectory() const;

	/**
	 * For dynamic plugins, returns the full path to the shared library
	 * from which it was loaded. For static plugins, returns an empty
	 * string.
	 **/
	const std::string& PluginPath() const;

	/**
	 * Returns the internal version of the Bro API that this plugin
	 * relies on. Only plugins that match Bro's current API version can
	 * be used. For statically compiled plugins this is automatically the
	 * case, but dynamically loaded plugins may cause a mismatch if they
	 * were compiled for a different Bro version.
	 */
	int APIVersion() const;

	/**
	 * Returns a list of all components the plugin provides.
	 */
	component_list Components() const;

	/**
	 * Returns a list of all BiF items that the plugin provides. This
	 * must be called only after InitBif() has been executed.
	 */
	bif_item_list BifItems() const;

	/**
	 * Returns a textual description of the plugin.
	 *
	 * @param d Description object to use for rendering. If "short mode"
	 * is disabled, the rendering will include a list of all components
	 * and BiF items.
	 */
	void Describe(ODesc* d) const;

	/**
	 * Registers an individual BiF that the plugin defines. The
	 * information is for informational purpuses only and will show up in
	 * the result of BifItems() as well as in the Describe() output.
	 * Another way to add this information is via overriding
	 * CustomBifItems().
	 *
	 * Note that this method is rarely the right one to use. As it's for
	 * informational purposes only, the plugin still needs to register
	 * the BiF items themselves with the corresponding Bro parts. Doing
	 * so can be tricky, and it's recommned to instead define BiF items
	 * in separate *.bif files that the plugin then pulls in. If defined
	 * there, one does *not* need to call this method.
	 *
	 * @param name The name of the BiF item.
	 *
	 * @param type The item's type.
	 */
	void AddBifItem(const std::string& name, BifItem::Type type);

	/**
	 * Adds a file to the list of files that Bro loads at startup. This
	 * will normally be a Bro script, but it passes through the plugin
	 * system as well to load files with other extensions as supported by
	 * any of the current plugins. In other words, calling this method is
	 * similar to giving a file on the command line. Note that the file
	 * may be only queued for now, and actually loaded later.
	 *
	 * This method must not be called after InitPostScript().
	 *
	 * @param file The file to load. It will be searched along the
	 * standard paths.
	 *
	 * @return True if successful (which however may only mean
	 * "successfully queued").
	 */
	bool LoadBroFile(const std::string& file);

protected:
	friend class Manager;

	/**
	 * First-stage initialization of the plugin called early during Bro's
	 * startup, before scripts are parsed. This can be overridden by
	 * derived classes; they must however call the parent's
	 * implementation.
	 */
	virtual void InitPreScript();

	/**
	 * Second-stage initialization of the plugin called late during Bro's
	 * startup, after scripts are parsed. This can be overridden by
	 * derived classes; they must however call the parent's
	 * implementation.
	 */
	virtual void InitPostScript();

	/**
	 * Finalizer method that derived classes can override for performing
	 * custom tasks at shutdown.  This can be overridden by derived
	 * classes; they must however call the parent's implementation.
	 */
	virtual void Done();

	/**
	 * Registers and activates a component.
	 *
	 * @param c The component. The method takes ownership.
	 */
	void AddComponent(Component* c);

	/**
	 * Enables a hook. The corresponding virtual method will now be
	 * called as Bro's processing proceeds. Note that enabling hooks can
	 * have performance impact as many trigger frequently inside Bro's
	 * main processing path.
	 *
	 * Note that while hooks may be enabled/disabled dynamically at any
	 * time, the output of Bro's \c -NN option will only reflect their
	 * state at startup time. Usually one should call this method for a
	 * plugin's hooks in either the plugin's constructor or in
	 * InitPreScript().
	 *
	 * @param hook The hook to enable.
	 *
	 * @param priority If multiple plugins enable the same hook, their
	 * priorities determine the order in which they'll be executed, from
	 * highest to lowest. If two plugins specify the same priority, order
	 * is undefined.
	 */
	void EnableHook(HookType hook, int priority = 0);

	/**
	 * Disables a hook. Bro will no longer call the corresponding virtual
	 * method.
	 *
	 * @param hook The hook to disable.
	 */
	void DisableHook(HookType hook);

	/**
	 * Returns a list of hooks that are currently enabled for the plugin,
	 * along with their priorities.
	 */
	hook_list EnabledHooks() const;

	/**
	 * Registers interest in an event, even if there's no handler for it.
	 * Normally a plugin receives events through HookQueueEvent() only if Bro
	 * actually has code to execute for it. By calling this method, the
	 * plugin tells Bro to raise the event even if there's no correspondong
	 * handler; it will then go into HookQueueEvent() just as any other.
	 *
	 * @param handler The event handler being interested in.
	 */
	void RequestEvent(EventHandlerPtr handler);

	/**
	 * Registers interest in the destruction of a BroObj instance. When
	 * Bro's reference counting triggers the objects destructor to run,
	 * \a HookBroObjDtor will be called.
	 *
	 * Note that his can get expensive if triggered for many objects.
	 *
	 * @param handler The object being interested in.
	 */
	void RequestBroObjDtor(BroObj* obj);

	// Hook functions.

	/**
	 * Hook into loading input files. This method will be called between
	 * InitPreScript() and InitPostScript(), but with no further order or
	 * timing guaranteed. It will be called once for each input file Bro
	 * is about to load, either given on the command line or via @load
	 * script directives. The hook can take over the file, in which case
	 * Bro will not further process it otherwise.
	 *
	 * @param file The filename to be loaded, including extension.
	 *
	 * @param ext The extension of the filename. This is provided
	 * separately just for convenience. The dot is excluded.
	 *
	 * @return 1 if the plugin took over the file and loaded it
	 * successfully; 0 if the plugin took over the file but had trouble
	 * loading it (Bro will abort in this case, and the plugin should
	 * have printed an error message); and -1 if the plugin wasn't
	 * interested in the file at all.
	 */
	virtual int HookLoadFile(const std::string& file, const std::string& ext);

	/**
	 * Hook into executing a script-level function/event/hook. Whenever
	 * the script interpreter is about to execution a function, it first
	 * gives all plugins with this hook enabled a chance to handle the
	 * call (in the order of their priorities). A plugin can either just
	 * inspect the call, or replace it (i.e., prevent the interpreter
	 * from executing it). In the latter case it must provide a matching
	 * return value.
	 *
	 * The default implementation never handles the call in any way.
	 *
	 * @param func The function being called.
	 *
	 * @param args The function arguments. The method can modify the list
	 * in place as long as it ensures matching types and correct reference
	 * counting.
	 *
	 * @return If the plugin handled the call, a std::pair<bool, Val*> with the
	 * processed flag set to true, and a value set on the object with
	 * a+1 reference count containing the result value to pass back to the
	 * interpreter.  If the plugin did not handle the call, it must
	 * return a pair with the processed flag set to 'false'.
	 */
	virtual std::pair<bool, Val*> HookCallFunction(const Func* func, Frame *parent, val_list* args);

	/**
	 * Hook into raising events. Whenever the script interpreter is about
	 * to queue an event for later execution, it first gives all plugins
	 * with this hook enabled a chance to handle the queuing otherwise
	 * (in the order of their priorities). A plugin can either just
	 * inspect the event, or take it over (i.e., prevent the interpreter
	 * from queuing it itself).
	 *
	 * The default implementation never handles the queuing in any way.
	 *
	 * @param event The event to be queued. The method can modify it in
	 * place as long as it ensures matching types and correct reference
	 * counting.
	 *
	 * @return True if the plugin took charge of the event; in that case
	 * it must have assumed ownership of the event and the interpreter will
	 * not do anything further with it. False otherwise.
	 */
	virtual bool HookQueueEvent(Event* event);

	/**
	 * Hook into event queue draining. This method will be called
	 * whenever the event manager is draining its queue.
	 */
	virtual void HookDrainEvents();

	/**
	 * Hook for updates to network time. This method will be called
	 * whenever network time is advanced.
	 *
	 * @param network_time The new network time.
	 */
	virtual void HookUpdateNetworkTime(double network_time);

	/**
	 * Hook for destruction of objects registered with
	 * RequestBroObjDtor(). When Bro's reference counting triggers the
	 * objects destructor to run, this method will be run. It may also
	 * run for other objects that this plugin has not registered for.
	 *
	 * @param obj A pointer to the object being destroyed. Note that the
	 * object is already considered invalid and the pointer must not be
	 * dereferenced.
	 */
	virtual void HookBroObjDtor(void* obj);

	// Meta hooks.

	/**
	 * A meta hook called just before another hook gets to execute. This
	 * will be called independent of whether there's an implementation
	 * for the hook.
	 *
	 * hook: The name of the hook about the execute. This will be the
	 * same as the corresponding method name (e.g., \c HookQueueEvent).
	 *
	 * hook: The type of the hook about to execute.
	 *
	 * args: A list of the hooks arguments.
	 */
	virtual void MetaHookPre(HookType hook, const HookArgumentList& args);

	/**
	 * A meta hook called just after another hook got to execute. This
	 * will be called independent of whether there's an implementation
	 * for the hook.
	 *
	 * hook: The type of the hook that finished executing.
	 *
	 * args: A list of the hooks arguments.
	 *
	 * result: The result that executing the hook returned. If there's no
	 * implementation for the hook, this will be the default result. If
	 * the hook doesn't yield a result, this will be of type VOID.
	 */
	virtual void MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result);

private:

	/**
	 * A function called when the plugin is instantiated to query basic
	 * configuration parameters.
	 *
	 * The plugin must override this method and return a suitably
	 * initialized configuration object.
	 *
	 * @return A configuration describing the plugin.
	 */
	virtual Configuration Configure() = 0;

	/**
	 * Intializes the plugin's internal configuration. Called by the
	 * manager before anything else.
	 */
	void DoConfigure();

	/**
	 * Sets the base directory and shared library path from which the
	 * plugin was loaded.
	 *
	 * This is called by the manager.
	 *
	 * @param dir The plugin directory. The functions makes an internal
	 * copy of string.
	 *
	 * @param sopath The full path the shared library loaded. The
	 * functions makes an internal copy of string.
	 */
	void SetPluginLocation(const std::string& dir, const std::string& sopath);

	/**
	 * Marks the plugin as dynamically loaded.
	 *
	 * This is called by the manager.
	 *
	 * @param is_dynamic True if it's a dynamically loaded module.
	 */
	void SetDynamic(bool is_dynamic);

	Configuration config;

	std::string base_dir;	// The plugin's base directory.
	std::string sopath;	// For dynamic plugins, the full path to the shared library.
	bool dynamic;	// True if a dynamic plugin.

	component_list components;	// Components the plugin provides.
	bif_item_list bif_items;	// BiF items the plugin provides.
};

}

#endif
